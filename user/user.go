// Copyright © 2019 yellowsea <hh1271941291@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package user

import (
	"context"
	"encoding/base64"
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

// Client provides the platform for user storing files in P2P network.
type Client struct {
	User         *tpUser.User
	PWD          string
	lastQueryEnd string
	QueryCache   map[string]*tpUser.User
	*p2p.UserNode
	*lib.ClientFramework
}

// NewUserClient is the construct for User's Client.
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
	return &Client{
		User:            u,
		PWD:             "/",
		UserNode:        n,
		ClientFramework: c,
		QueryCache:      make(map[string]*tpUser.User),
	}, nil
}

// Sync get user's data from blockchain.
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

// UserRegister register user in the blockchain.
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

// fixPath fix the operation path with PWD.
func (c *Client) fixPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(c.PWD, p)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return p
}

// splitPathName split the path into target's parent path and target's name.
func (c *Client) splitPathName(p string) (string, string) {
	pathParams := strings.Split(c.fixPath(p), "/")
	p = strings.Join(pathParams[:len(pathParams)-2], "/") + "/"
	name := pathParams[len(pathParams)-2]
	return p, name
}

// ChangePWD changed the PWD to destination path.
func (c *Client) ChangePWD(dst string) error {
	dst = c.fixPath(dst)
	_, err := c.User.Root.GetDirectory(dst)
	if err != nil {
		return err
	}
	c.PWD = dst
	return nil
}

// GetSize returns the total size of files stored in P2P network.
func (c *Client) GetSize() int64 {
	return c.User.Root.Home.Size
}

// GetINode returns the iNode of the path in 'home' directory.
// If error is not nil, it will return.
func (c *Client) GetINode(p string) (tpStorage.INode, error) {
	p, name := c.splitPathName(p)
	return c.User.Root.GetINode(p, name)
}

// GetSharedINode returns the iNode of the path in 'shared' directory.
// If error is not nil, it will return./
func (c *Client) GetSharedINode(p string) (tpStorage.INode, error) {
	p, name := c.splitPathName(p)
	return c.User.Root.GetSharedINode(p, name)
}

// TODO: Create Directory & Create All Directory

// CreateDirectory create new directory of the path and send transaction.
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

// CreateFile create new file of the source.
// After sending transaction, upload file into P2P network.
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

	seas, err := lib.ListSeasPublicKey("", lib.DefaultQueryLimit)
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

// uploadFile upload file into P2P network.
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

// Rename change the target name to new name.
func (c *Client) Rename(src, newName string) (map[string]interface{}, error) {
	p, name := c.splitPathName(src)
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

// ListDirectory returns the information of iNodes in the path of 'home' directory.
func (c *Client) ListDirectory(p string) ([]tpStorage.INodeInfo, error) {
	return c.User.Root.ListDirectory(c.fixPath(p))
}

// ListSharedDirectory returns the information of iNodes in the path of 'shared' directory.
func (c *Client) ListSharedDirectory(p string) ([]tpStorage.INodeInfo, error) {
	return c.User.Root.ListSharedDirectory(c.fixPath(p))
}

// DeleteDirectory delete directory of the path in 'home' directory and files under it.
// After delete it, send transaction.
func (c *Client) DeleteDirectory(p string) (map[string]interface{}, error) {
	p, name := c.splitPathName(p)
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

// DeleteFile delete the target file, then send transaction.
func (c *Client) DeleteFile(p string) (map[string]interface{}, error) {
	p, name := c.splitPathName(p)
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

// Move change the iNode's parent path from source to destination.
func (c *Client) Move(src, dst string) (map[string]interface{}, error) {
	dst = c.fixPath(dst)
	p, name := c.splitPathName(src)
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

// DownloadFiles download the file or directory to destination path in system.
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

// DownloadSharedFiles download the file or directory in 'shared' directory of owner to destination path in system.
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

// download files in it and recursive call to download directories in it.
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

// download file of the target path.
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

// PublishKey publish keys of the files in the path.
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

// publish keys of the files in the directory.
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

// publish key of the file.
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

// ShareFiles share the files from 'home' directory to 'shared' directory.
func (c *Client) ShareFiles(src, dst string) (map[string]string, map[string]interface{}, error) {
	dst = c.fixPath(dst)
	p, name := c.splitPathName(src)
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

// ListUsersShared get the query cache for list shared files.
func (c *Client) ListUsersShared(other bool) error {
	if len(c.QueryCache) == 0 {
		users, err := lib.ListUsers("", lib.DefaultQueryLimit)
		if err != nil {
			return err
		}
		for _, u := range users {
			m := u.(map[string]interface{})
			userBytes, err := base64.StdEncoding.DecodeString(m["data"].(string))
			if err != nil {
				continue
			}
			u, err := tpUser.UserFromBytes(userBytes)
			if err != nil {
				continue
			}
			c.QueryCache[m["address"].(string)] = u
		}
	} else if other {
		users, err := lib.ListUsers(c.lastQueryEnd, lib.DefaultQueryLimit+1)
		if err != nil {
			return err
		}
		for k := range c.QueryCache {
			delete(c.QueryCache, k)
		}
		for i := 1; i < len(users); i++ {
			m := users[i].(map[string]interface{})
			userBytes, err := base64.StdEncoding.DecodeString(m["data"].(string))
			if err != nil {
				continue
			}
			u, err := tpUser.UserFromBytes(userBytes)
			if err != nil {
				continue
			}
			c.QueryCache[m["address"].(string)] = u
		}
	}
	return nil
}

// ListOtherSharedDirectory returns the list of user's shared directory.
// If error is not nil, it will return.
func (c *Client) ListOtherSharedDirectory(owner, p string) ([]tpStorage.INodeInfo, error) {
	u, err := c.checkUser(owner)
	if err != nil {
		return nil, err
	}
	return u.Root.ListSharedDirectory(p)
}

// GetOtherSharedINode returns the iNode of user's shared files.
// If error is not nil, it will return.
func (c *Client) GetOtherSharedINode(owner, p string) (tpStorage.INode, error) {
	u, err := c.checkUser(owner)
	if err != nil {
		return nil, err
	}
	p, name := c.splitPathName(p)
	return u.Root.GetSharedINode(p, name)
}

// check user whether in the query cache.
// If exists, it will return directly.
// Else it will get user's data from blockchain.
func (c *Client) checkUser(addr string) (*tpUser.User, error) {
	u, ok := c.QueryCache[addr]
	if !ok {
		userBytes, err := lib.GetStateData(addr)
		if err != nil {
			return nil, err
		}
		u, err = tpUser.UserFromBytes(userBytes)
		if err != nil {
			return nil, err
		}
		c.QueryCache[addr] = u
	}
	return u, nil
}
