package user

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p"
	p2pCrypto "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpPayload "gitlab.com/SeaStorage/SeaStorage-TP/payload"
	tpStorage "gitlab.com/SeaStorage/SeaStorage-TP/storage"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p"
)

type Client struct {
	User *tpUser.User
	PWD  string
	*p2p.UserNode
	*lib.ClientFramework
}

func NewUserClient(name, keyFile string) (*Client, error) {
	c, err := lib.NewClientFramework(name, lib.ClientCategoryUser, keyFile)
	if err != nil {
		return nil, err
	}
	var u *tpUser.User
	userBytes, _ := c.GetData()
	if userBytes != nil {
		logrus.WithField("username", name).Info("user login success")
		u, err = tpUser.UserFromBytes(userBytes)
		if err != nil {
			u = nil
			logrus.Error(err)
		}
	}
	priv, _ := ioutil.ReadFile(keyFile)
	privateKey, err := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(priv)))
	if err != nil {
		return nil, err
	}
	multiAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", lib.ListenAddress, lib.ListenPort))
	if err != nil {
		return nil, err
	}
	host, err := libp2p.New(context.Background(), libp2p.ListenAddrs(multiAddr), libp2p.Identity(privateKey))
	if err != nil {
		return nil, err
	}
	n := p2p.NewUserNode(host)
	return &Client{User: u, PWD: "/", UserNode: n, ClientFramework: c}, nil
}

func (c *Client) UserRegister() error {
	_, err := c.Register(c.Name)
	if err != nil {
		return err
	}
	logrus.WithFields(logrus.Fields{
		"name":       c.Name,
		"public key": c.GetPublicKey(),
		"address":    c.GetAddress(),
	}).Info("user register success")
	return c.Sync()
}

func (c *Client) ChangePWD(dst string) error {
	if !strings.HasPrefix(dst, "/") {
		dst = path.Join(c.PWD, dst)
	}
	if !strings.HasSuffix(dst, "/") {
		dst += "/"
	}
	_, err := c.User.Root.GetDirectory(dst)
	if err != nil {
		return err
	}
	c.PWD = dst
	return nil
}

func (c *Client) GetSize() int64 {
	return c.User.Root.Home.Size
}

func (c *Client) GetINode(p string) (tpStorage.INode, error) {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	pathParams := strings.Split(p, "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	return c.User.Root.GetINode(p, name)
}

func (c *Client) CreateDirectory(p string) (map[string]interface{}, error) {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	err := c.User.Root.CreateDirectory(p)
	if err != nil {
		return nil, err
	}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserCreateDirectory,
		Name:   c.Name,
		PWD:    p,
	}}, lib.DefaultWait)
	return response, err
}

func (c *Client) CreateFile(src, dst string, dataShards, parShards int) (map[string]interface{}, error) {
	if !strings.HasPrefix(src, "/") {
		return nil, errors.New("the source path should be full path")
	}
	if !strings.HasPrefix(dst, "/") {
		dst = path.Join(c.PWD, dst)
	}
	if !strings.HasSuffix(dst, "/") {
		dst += "/"
	}
	// Check Destination Path exists
	_, err := c.User.Root.GetDirectory(dst)
	if err != nil {
		return nil, err
	}
	info, err := crypto.GenerateFileInfo(src, dataShards, parShards)
	if err != nil {
		return nil, err
	}
	err = c.User.Root.CreateFile(dst, info)
	if err != nil {
		return nil, err
	}

	// TODO: 并行监视transaction完成情况，通过channel控制文件上传

	go func() {
		seas, err := lib.ListSeasPeerId("", 20)
		if err != nil || len(seas) == 0 {
			logrus.Error("failed to get seas:", err)
			return
		}
		fragmentSeas := make([][]peer.ID, 0)
		for i := range info.Fragments {
			// TODO: Algorithm for select sea && user selected seas
			fragmentSeas = append(fragmentSeas, []peer.ID{seas[i%len(seas)], seas[(i+3)%len(seas)], seas[(i+5)%len(seas)]})
		}
		err = c.UploadFiles(info, dst, fragmentSeas)
		if err != nil {
			logrus.Error(err)
			return
		}
	}()
	return c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action:   tpPayload.UserCreateFile,
		Name:     c.Name,
		PWD:      dst,
		FileInfo: info,
	}}, lib.DefaultWait)
}

func (c *Client) ListDirectory(p string) ([]tpStorage.INodeInfo, error) {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return c.User.Root.ListDirectory(p)
}

func (c *Client) DeleteDirectory(p string) (map[string]interface{}, error) {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	pathParams := strings.Split(p, "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	err := c.User.Root.DeleteDirectory(p, name)
	if err != nil {
		return nil, err
	}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserDeleteDirectory,
		Name:   c.Name,
		PWD:    p,
		Target: name,
	}}, lib.DefaultWait)
	return response, err
}

func (c *Client) DeleteFile(p string) (map[string]interface{}, error) {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	pathParams := strings.Split(p, "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	err := c.User.Root.DeleteFile(p, name)
	if err != nil {
		return nil, err
	}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserDeleteFile,
		Name:   c.Name,
		PWD:    p,
		Target: name,
	}}, lib.DefaultWait)
	return response, err
}

func (c *Client) DownloadFiles(p, dst string) {
	iNode, err := c.GetINode(p)
	if err != nil {
		fmt.Println(err)
		return
	}
	switch iNode.(type) {
	case *tpStorage.File:
		c.downloadFile(iNode.(*tpStorage.File), dst)
	case *tpStorage.Directory:
		c.downloadDirectory(iNode.(*tpStorage.Directory), dst)
	}
}

func (c *Client) downloadDirectory(dir *tpStorage.Directory, dst string) {
	for _, iNode := range dir.INodes {
		switch iNode.(type) {
		case *tpStorage.File:
			go c.downloadFile(iNode.(*tpStorage.File), path.Join(dst, dir.Name))
		case *tpStorage.Directory:
			go c.downloadDirectory(iNode.(*tpStorage.Directory), path.Join(dst, dir.Name))
		}
	}
}

func (c *Client) downloadFile(f *tpStorage.File, dst string) {
	err := os.MkdirAll(path.Join(lib.DefaultTmpPath, f.Hash), 0755)
	if err != nil {
		fmt.Println(err)
		return
	}
	errCount := 0
	storagePath := path.Join(lib.DefaultTmpPath, f.Hash)
	for i, fragment := range f.Fragments {
		if i-errCount == lib.DefaultDataShards {
			break
		}
		err = c.DownloadFragment(storagePath, fragment)
		if err != nil {
			errCount++
		}
	}
	if errCount >= lib.DefaultParShards {
		fmt.Println("not enough sources")
		return
	}
	outFile, err := os.OpenFile(path.Join(lib.DefaultTmpPath, f.Hash, f.Name+".enc"), os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
	hashes := make([]string, len(f.Fragments))
	for i := range f.Fragments {
		hashes[i] = f.Fragments[i].Hash
	}
	err = crypto.MergeFile(path.Join(lib.DefaultTmpPath, f.Hash), hashes, outFile, int(f.Size), lib.DefaultDataShards, lib.DefaultParShards)
	if err != nil {
		fmt.Println(err)
		return
	}
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		err := os.MkdirAll(dst, 0755)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	outFile.Close()
	inFile, err := os.Open(outFile.Name())
	defer inFile.Close()
	dstFile, err := os.OpenFile(path.Join(dst, f.Name), os.O_CREATE|os.O_WRONLY, 0644)
	defer dstFile.Close()
	hash, err := crypto.DecryptFile(inFile, dstFile, tpCrypto.HexToBytes(c.User.Root.Keys[f.KeyIndex].Key))
	if err != nil {
		fmt.Println(err)
		return
	}
	if f.Hash != hash {
		fmt.Println(errors.New("invalid hash"))
	} else {
		fmt.Println("download success:", dstFile.Name())
	}
}

func (c *Client) Sync() error {
	userBytes, err := c.GetData()
	if err != nil {
		return err
	}
	u, err := tpUser.UserFromBytes(userBytes)
	if err != nil {
		return err
	}
	c.User = u
	return nil
}

func (c *Client) UploadFiles(fileInfo tpStorage.FileInfo, dst string, seas [][]peer.ID) error {
	if len(seas) != len(fileInfo.Fragments) {
		return errors.New("the storage destination is not enough")
	}

	var err error
	var wg sync.WaitGroup
	for i, fragment := range fileInfo.Fragments {
		f, subErr := os.Open(path.Join(lib.DefaultTmpPath, fileInfo.Hash, fmt.Sprintf("%s.%d", fileInfo.Hash, i)))
		defer func() {
			f.Close()
			os.Remove(path.Join(lib.DefaultTmpPath, fileInfo.Hash, fmt.Sprintf("%s.%d", fileInfo.Hash, i)))
		}()
		if subErr != nil && os.IsNotExist(subErr) {
			continue
		}
		stat, subErr := f.Stat()
		if subErr != nil {
			continue
		}
		operation := c.GenerateOperation(dst, fileInfo.Name, fragment.Hash, stat.Size())
		wg.Add(1)
		go func(operation *tpUser.Operation) {
			err = c.UploadFile(f, operation, seas[i])
			if err != nil {
				logrus.WithField("hash", fragment.Hash).Error(err)
			}
		}(operation)
	}
	wg.Wait()
	return err
}
