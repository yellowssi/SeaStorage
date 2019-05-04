package user

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage-TP/payload"
	"gitlab.com/SeaStorage/SeaStorage-TP/storage"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

type Client struct {
	User            *tpUser.User
	PWD             string
	ClientFramework *lib.ClientFramework
}

func NewUserClient(name string, url string, keyFile string) (*Client, error) {
	c, err := lib.NewClient(name, lib.ClientCategoryUser, url, keyFile)
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
	return &Client{User: u, PWD: "/", ClientFramework: c}, nil
}

func (c *Client) Register() (err error) {
	_, err = c.ClientFramework.Register(c.ClientFramework.Name)
	if err != nil {
		return err
	}
	logrus.WithFields(logrus.Fields{
		"name": c.ClientFramework.Name,
		"public key": c.ClientFramework.GetPublicKey(),
		"address": c.ClientFramework.GetAddress(),
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

func (c *Client) GetSize() int {
	return c.User.Root.Home.Size
}

func (c *Client) GetINode(p string) (storage.INode, error) {
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
	response, err := c.ClientFramework.SendTransaction([]payload.SeaStoragePayload{{
		Action: payload.UserCreateDirectory,
		Name:   c.ClientFramework.Name,
		PWD:    p,
	}}, lib.DefaultWait)
	return response, err
}

func (c *Client) CreateFile(src, dst string, dataShards, parShards int) (map[string]interface{}, error) {
	if !strings.HasPrefix(src, "/") {
		return nil, errors.New("the source path should be full path")
	}
	info, err := crypto.GenerateFileInfo(src, dataShards, parShards)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(dst, "/") {
		dst = path.Join(c.PWD, dst)
	}
	if !strings.HasSuffix(dst, "/") {
		dst += "/"
	}
	err = c.User.Root.CreateFile(dst, info)
	if err != nil {
		return nil, err
	}
	response, err := c.ClientFramework.SendTransaction([]payload.SeaStoragePayload{{
		Action:   payload.UserCreateFile,
		Name:     c.ClientFramework.Name,
		PWD:      dst,
		FileInfo: info,
	}}, lib.DefaultWait)
	return response, err
}

func (c *Client) ListDirectory(p string) ([]storage.INodeInfo, error) {
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
	response, err := c.ClientFramework.SendTransaction([]payload.SeaStoragePayload{{
		Action: payload.UserDeleteDirectory,
		Name:   c.ClientFramework.Name,
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
	response, err := c.ClientFramework.SendTransaction([]payload.SeaStoragePayload{{
		Action: payload.UserDeleteFile,
		Name:   c.ClientFramework.Name,
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
	case *storage.File:
		c.downloadFile(iNode.(*storage.File), dst)
	case *storage.Directory:
		c.downloadDirectory(iNode.(*storage.Directory), dst)
	}
}

func (c *Client) downloadDirectory(dir *storage.Directory, dst string) {
	for _, iNode := range dir.INodes {
		switch iNode.(type) {
		case *storage.File:
			go c.downloadFile(iNode.(*storage.File), path.Join(dst, dir.Name))
		case *storage.Directory:
			go c.downloadDirectory(iNode.(*storage.Directory), path.Join(dst, dir.Name))
		}
	}
}

func (c *Client) downloadFile(f *storage.File, dst string) {
	err := os.MkdirAll(path.Join(lib.DefaultTmpPath, f.Hash), 0755)
	if err != nil {
		fmt.Println(err)
		return
	}
	errCount := 0
	for i, fragment := range f.Fragments {
		if i-errCount == lib.DefaultDataShards {
			break
		}
		err = p2p.DownloadFile(fragment.Hash, path.Join(lib.DefaultTmpPath, f.Hash))
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
	userBytes, err := c.ClientFramework.GetData()
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

func (c *Client) uploadFiles(fileInfo storage.FileInfo, src, dst, name string, seas []string) error {
	if len(seas) != len(fileInfo.Fragments) {
		return errors.New("the storage destination is not enough")
	}

	var err error
	var wg sync.WaitGroup
	for i := range fileInfo.Fragments {
		f, subErr := os.Open(path.Join(src, fileInfo.Fragments[i].Hash))
		if subErr != nil && os.IsNotExist(subErr) {
			continue
		}
		signature := c.ClientFramework.GenerateOperationSignature(tpUser.NewOperation(c.ClientFramework.Name, c.ClientFramework.GetPublicKey(), dst, name, time.Now()))
		wg.Add(1)
		go func(signature tpUser.OperationSignature) {
			err = p2p.UploadFile(f, seas[i], signature)
			if err != nil {
				logrus.WithField("hash", fileInfo.Fragments[i].Hash).Error(err)
			}
		}(*signature)
	}
	wg.Wait()
	return err
}
