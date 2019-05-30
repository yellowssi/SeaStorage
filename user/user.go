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
	p2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	p2pDHT "github.com/libp2p/go-libp2p-kad-dht"
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

func NewUserClient(name, keyFile string, bootstrapAddrs []ma.Multiaddr) (*Client, error) {
	c, err := lib.NewClientFramework(name, lib.ClientCategoryUser, keyFile)
	if err != nil {
		return nil, err
	}
	var u *tpUser.User
	userBytes, _ := c.GetData()
	if userBytes != nil {
		lib.Logger.WithField("username", name).Info("user login success")
		u, err = tpUser.UserFromBytes(userBytes)
		if err != nil {
			u = nil
			lib.Logger.Error(err)
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
	ctx := context.Background()
	host, err := libp2p.New(ctx, libp2p.ListenAddrs(multiAddr), libp2p.Identity(privateKey))
	if err != nil {
		return nil, err
	}
	n := p2p.NewUserNode(host, c)
	// TODO: 当用户需要是启动监听，上传或下载结束后停止监听
	kadDHT, err := p2pDHT.New(ctx, host)
	if err != nil {
		return nil, err
	}
	if err = kadDHT.Bootstrap(ctx); err != nil {
		return nil, err
	}
	var wg sync.WaitGroup
	for _, addr := range bootstrapAddrs {
		peerInfo, err := p2pPeer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"peer": addr,
			}).Warn("failed to get peer info:", err)
			continue
		}
		wg.Add(1)
		go func(info p2pPeer.AddrInfo) {
			defer wg.Done()
			err = host.Connect(ctx, info)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"peer": info,
				}).Warn("failed to connect peer:", err)
			}
		}(*peerInfo)
	}
	wg.Wait()
	return &Client{User: u, PWD: "/", UserNode: n, ClientFramework: c}, nil
}

// Sync user info from blockchain
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

// User register in the blockchain
func (c *Client) UserRegister() error {
	_, err := c.Register(c.Name)
	if err != nil {
		return err
	}
	lib.Logger.WithFields(logrus.Fields{
		"name":       c.Name,
		"public key": c.GetPublicKey(),
		"address":    c.GetAddress(),
	}).Info("user register success")
	return c.Sync()
}

// Fix Operation path
func (c *Client) fixPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// Change Operation PWD
func (c *Client) ChangePWD(dst string) error {
	dst = c.fixPath(dst)
	_, err := c.User.Root.GetDirectory(dst)
	if err != nil {
		return err
	}
	c.PWD = dst
	return nil
}

// Get the total size of user's storage
func (c *Client) GetSize() int64 {
	return c.User.Root.Home.Size
}

// Get iNode of the path in home directory
func (c *Client) GetINode(p string) (tpStorage.INode, error) {
	pathParams := strings.Split(c.fixPath(p), "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	return c.User.Root.GetINode(p, name)
}

// Get iNode of the path in shared directory
func (c *Client) GetSharedINode(p string) (tpStorage.INode, error) {
	pathParams := strings.Split(c.fixPath(p), "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	return c.User.Root.GetSharedINode(p, name)
}

// TODO: Create Directory & Create All Directory
// Create all directory of the path
func (c *Client) CreateDirectory(p string) (map[string]interface{}, error) {
	p = c.fixPath(p)
	err := c.User.Root.CreateDirectory(p)
	if err != nil {
		return nil, err
	}
	addresses := []string{c.GetAddress()}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserCreateDirectory,
		Name:   c.Name,
		PWD:    p,
	}}, addresses, addresses, lib.DefaultWait)
	return response, err
}

// Upload src file in the dst path
func (c *Client) CreateFile(src, dst string, dataShards, parShards int) (map[string]interface{}, error) {
	if !strings.HasPrefix(src, "/") {
		return nil, errors.New("the source path should be full path")
	}
	dst = c.fixPath(dst)
	// Check Destination Path exists
	_, err := c.User.Root.GetDirectory(dst)
	if err != nil {
		return nil, err
	}
	info, err := crypto.GenerateFileInfo(src, c.GetPublicKey(), dataShards, parShards)
	if err != nil {
		return nil, err
	}
	err = c.User.Root.CreateFile(dst, info)
	if err != nil {
		return nil, err
	}

	seas, err := lib.ListSeasPublicKey("", 20)
	if err != nil || len(seas) == 0 {
		return nil, err
	}

	addresses := []string{c.GetAddress()}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action:   tpPayload.UserCreateFile,
		Name:     c.Name,
		PWD:      dst,
		FileInfo: info,
	}}, addresses, addresses, lib.DefaultWait)

	if err != nil {
		return nil, err
	}
	// TODO: Watching transaction status
	fragmentSeas := make([][]string, 0)
	for i := range info.Fragments {
		// TODO: Algorithm for select sea && user selected seas
		peers := make([]string, 0)
		if len(seas) <= 3 {
			peers = append(peers, seas...)
		} else {
			for j := i; j <= i+len(seas); j++ {
				peers = append(peers, seas[j%len(seas)])
				if len(peers) >= 3 {
					break
				}
			}
		}
		fragmentSeas = append(fragmentSeas, peers)
	}
	c.uploadFile(info, dst, fragmentSeas)
	return response, nil
}

// Upload the file into the seas
func (c *Client) uploadFile(fileInfo tpStorage.FileInfo, dst string, seas [][]string) {
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
		wg.Add(1)
		go func(src *os.File, hash string, size int64, seas []string) {
			defer wg.Done()
			c.Upload(src, dst, fileInfo.Name, hash, size, seas)
		}(f, fragment.Hash, fragment.Size, seas[i])
	}
	wg.Wait()
	lib.Logger.WithFields(logrus.Fields{}).Info("file upload finish")
}

// Rename the file or directory
func (c *Client) Rename(src, newName string) (map[string]interface{}, error) {
	src = c.fixPath(src)
	pathParams := strings.Split(src, "/")
	p := strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	err := c.User.Root.UpdateName(p, name, newName)
	if err != nil {
		return nil, err
	}
	addresses := []string{c.GetAddress()}
	return c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Name:   c.Name,
		Action: tpPayload.UserUpdateName,
		PWD:    p,
		Target: []string{name, newName},
	}}, addresses, addresses, lib.DefaultWait)
}

// List directory infos in the path of home directory
func (c *Client) ListDirectory(p string) ([]tpStorage.INodeInfo, error) {
	return c.User.Root.ListDirectory(c.fixPath(p))
}

// List directory infos in the path of shared directory
func (c *Client) ListSharedDirectory(p string) ([]tpStorage.INodeInfo, error) {
	return c.User.Root.ListSharedDirectory(c.fixPath(p))
}

// Delete the directory of the path
func (c *Client) DeleteDirectory(p string) (map[string]interface{}, error) {
	p = c.fixPath(p)
	pathParams := strings.Split(p, "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	seaOperations, err := c.User.Root.DeleteDirectory(p, name, true)
	if err != nil {
		return nil, err
	}
	addresses := []string{c.GetAddress()}
	for addr := range seaOperations {
		addresses = append(addresses, addr)
	}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserDeleteDirectory,
		Name:   c.Name,
		PWD:    p,
		Target: []string{name},
	}}, addresses, addresses, lib.DefaultWait)
	return response, err
}

// Delete the file of the path
func (c *Client) DeleteFile(p string) (map[string]interface{}, error) {
	p = c.fixPath(p)
	pathParams := strings.Split(p, "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	seaOperations, err := c.User.Root.DeleteFile(p, name, true)
	if err != nil {
		return nil, err
	}
	addresses := []string{c.GetAddress()}
	for addr := range seaOperations {
		addresses = append(addresses, addr)
	}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserDeleteFile,
		Name:   c.Name,
		PWD:    p,
		Target: []string{name},
	}}, addresses, addresses, lib.DefaultWait)
	return response, err
}

// Move file or directory to new path
func (c *Client) Move(src, dst string) (map[string]interface{}, error) {
	src = c.fixPath(src)
	dst = c.fixPath(dst)
	pathParams := strings.Split(src, "/")
	p := strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	err := c.User.Root.Move(p, name, dst)
	if err != nil {
		return nil, err
	}
	addresses := []string{c.GetAddress()}
	return c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Name:   c.Name,
		Action: tpPayload.UserMove,
		PWD:    p,
		Target: []string{name, dst},
	}}, addresses, addresses, lib.DefaultWait)
}

// Download the file of the path into the dst path in the system
func (c *Client) DownloadFiles(p, dst string) {
	iNode, err := c.GetINode(p)
	if err != nil {
		fmt.Println(err)
		return
	}
	switch iNode.(type) {
	case *tpStorage.File:
		c.downloadFile(iNode.(*tpStorage.File), "", dst)
	case *tpStorage.Directory:
		wg := &sync.WaitGroup{}
		wg.Add(1)
		c.downloadDirectory(iNode.(*tpStorage.Directory), "", dst, wg)
		wg.Wait()
	}
}

// Download the shared file of owner in the path into the dst path in the system
func (c *Client) DownloadSharedFiles(p, dst, owner string) {
	iNode, err := c.GetINode(p)
	if err != nil {
		fmt.Println(err)
		return
	}
	switch iNode.(type) {
	case *tpStorage.File:
		c.downloadFile(iNode.(*tpStorage.File), owner, dst)
	case *tpStorage.Directory:
		wg := &sync.WaitGroup{}
		wg.Add(1)
		c.downloadDirectory(iNode.(*tpStorage.Directory), owner, dst, wg)
		wg.Wait()
	}
}

// Download the directory and all the files in it into the dst path in the system
func (c *Client) downloadDirectory(dir *tpStorage.Directory, owner, dst string, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, iNode := range dir.INodes {
		switch iNode.(type) {
		case *tpStorage.File:
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.downloadFile(iNode.(*tpStorage.File), owner, path.Join(dst, dir.Name))
			}()
		case *tpStorage.Directory:
			wg.Add(1)
			go c.downloadDirectory(iNode.(*tpStorage.Directory), owner, path.Join(dst, dir.Name), wg)
		}
	}
}

// Download the file into the dst path in the system
func (c *Client) downloadFile(f *tpStorage.File, owner, dst string) {
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
		err = c.Download(storagePath, owner, fragment)
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
		fmt.Println("failed to open file:", err)
		return
	}
	hashes := make([]string, len(f.Fragments))
	for i := range f.Fragments {
		hashes[i] = f.Fragments[i].Hash
	}
	err = crypto.MergeFile(path.Join(lib.DefaultTmpPath, f.Hash), hashes, outFile, int(f.Size), lib.DefaultDataShards, lib.DefaultParShards)
	if err != nil {
		fmt.Println("failed to merge file:", err)
		return
	}
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		err := os.MkdirAll(dst, 0755)
		if err != nil {
			fmt.Println("failed to create the destination directory:", err)
			return
		}
	}
	outFile.Close()
	inFile, err := os.Open(outFile.Name())
	defer inFile.Close()
	dstFile, err := os.OpenFile(path.Join(dst, f.Name), os.O_CREATE|os.O_WRONLY, 0644)
	defer dstFile.Close()
	key, err := c.DecryptFileKey(c.User.Root.Keys[f.KeyIndex].Key)
	if err != nil {
		fmt.Println("failed to decrypt file key:", err)
		return
	}
	hash, err := crypto.DecryptFile(inFile, dstFile, key)
	if err != nil {
		fmt.Println("failed to decrypt file:", err)
		return
	}
	if f.Hash != hash {
		fmt.Println(errors.New("invalid hash"))
	} else {
		fmt.Println("download success:", dstFile.Name())
	}
}

// Publish keys of the files in the path
func (c *Client) PublishKey(p string) (map[string]interface{}, error) {
	iNode, err := c.GetINode(p)
	if err != nil {
		return nil, err
	}
	addresses := []string{c.GetAddress()}
	switch iNode.(type) {
	case *tpStorage.File:
		key, err := c.publishFileKey(iNode.(*tpStorage.File))
		if err != nil {
			return nil, err
		}
		return c.SendTransaction(
			[]tpPayload.SeaStoragePayload{{Action: tpPayload.UserPublishKey, Key: key}},
			addresses,
			addresses,
			lib.DefaultWait)
	case *tpStorage.Directory:
		payloadMap, err := c.publishDirectoryKey(iNode.(*tpStorage.Directory))
		if err != nil {
			return nil, err
		}
		payloads := make([]tpPayload.SeaStoragePayload, 0)
		for _, payload := range payloadMap {
			payloads = append(payloads, payload)
		}
		return c.SendTransaction(payloads, addresses, addresses, lib.DefaultWait)
	}
	return nil, errors.New("failed to public key")
}

// Publish keys of the files in the directory
func (c *Client) publishDirectoryKey(dir *tpStorage.Directory) (map[string]tpPayload.SeaStoragePayload, error) {
	payloads := make(map[string]tpPayload.SeaStoragePayload)
	for _, iNode := range dir.INodes {
		switch iNode.(type) {
		case *tpStorage.File:
			key, err := c.publishFileKey(iNode.(*tpStorage.File))
			if err != nil {
				return nil, err
			}
			_, ok := payloads[key]
			if !ok {
				payloads[key] = tpPayload.SeaStoragePayload{Action: tpPayload.UserPublishKey, Key: key}
			}
		case *tpStorage.Directory:
			subPayloads, err := c.publishDirectoryKey(iNode.(*tpStorage.Directory))
			if err != nil {
				return nil, err
			}
			for key, payload := range subPayloads {
				_, ok := payloads[key]
				if !ok {
					payloads[key] = payload
				}
			}
		}
	}
	return payloads, nil
}

// Publish key of the file
func (c *Client) publishFileKey(file *tpStorage.File) (key string, err error) {
	keyBytes, err := c.DecryptFileKey(c.User.Root.Keys[file.KeyIndex].Key)
	if err != nil {
		return
	}
	key = tpCrypto.BytesToHex(keyBytes)
	err = c.User.Root.PublishKey(c.GetPublicKey(), key)
	if err != nil {
		return
	}
	return key, nil
}

// Share Files
func (c *Client) ShareFiles(src, dst string) (map[string]string, map[string]interface{}, error) {
	src = c.fixPath(src)
	dst = c.fixPath(dst)
	pathParams := strings.Split(src, "/")
	p := strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	seaOperations, keys, err := c.User.Root.ShareFiles(p, name, dst, true)
	if err != nil {
		return nil, nil, err
	}
	addresses := []string{c.GetAddress()}
	for addr := range seaOperations {
		addresses = append(addresses, addr)
	}
	response, err := c.SendTransaction([]tpPayload.SeaStoragePayload{{
		Name:   c.Name,
		Action: tpPayload.UserShare,
		PWD:    p,
		Target: []string{name, dst},
	}}, addresses, addresses, lib.DefaultWait)
	return keys, response, err
}
