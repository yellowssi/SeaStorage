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

// Package user provides the client platform for user.
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
	tpCrypto "github.com/yellowssi/SeaStorage-TP/crypto"
	tpPayload "github.com/yellowssi/SeaStorage-TP/payload"
	tpStorage "github.com/yellowssi/SeaStorage-TP/storage"
	tpUser "github.com/yellowssi/SeaStorage-TP/user"
	"github.com/yellowssi/SeaStorage/crypto"
	"github.com/yellowssi/SeaStorage/lib"
	"github.com/yellowssi/SeaStorage/p2p"
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
	ip4Ma, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", lib.IPv4ListenAddress, lib.ListenPort))
	if err != nil {
		return nil, err
	}
	ip6Ma, err := ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/tcp/%d", lib.IPv6ListenAddress, lib.ListenPort))
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	host, err := libp2p.New(ctx, libp2p.ListenAddrs(ip4Ma, ip6Ma), libp2p.Identity(privateKey))
	if err != nil {
		return nil, err
	}
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
	n := p2p.NewUserNode(ctx, host, kadDHT, c)
	cli := &Client{
		User:            u,
		PWD:             "/",
		UserNode:        n,
		ClientFramework: c,
		QueryCache:      make(map[string]*tpUser.User),
	}
	go func() {
		var data []byte
		for {
			data = <-cli.State
			u, err := tpUser.UserFromBytes(data)
			if err != nil {
				lib.Logger.Errorf("failed to sync: %v", err)
			} else {
				cli.User = u
			}
		}
	}()
	return cli, nil
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
	err := c.Register(c.Name)
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

// CreateDirectory create new directory of the path and send transaction.
func (c *Client) CreateDirectory(p string) error {
	p = c.fixPath(p)
	err := c.User.Root.CreateDirectory(p)
	if err != nil {
		return err
	}
	addresses := []string{c.GetAddress()}
	err = c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserCreateDirectory,
		Name:   c.Name,
		PWD:    p,
	}}, addresses, addresses)
	return err
}

// CreateDirectoryWithFiles upload directory and files in it from source path in system to destination path.
func (c *Client) CreateDirectoryWithFiles(src, dst string, dataShards, parShards int) error {
	dst = c.fixPath(dst)
	keyAES := tpCrypto.GenerateRandomAESKey(lib.AESKeySize)
	payloads, infos, err := c.generateCreateDirectoryAndFilesPayload(src, dst, tpCrypto.BytesToHex(keyAES), dataShards, parShards)
	if err != nil {
		return err
	}
	fileSeas := make([][][]string, 0)
	for _, info := range infos {
		fileInfo := info["info"].(tpStorage.FileInfo)
		seas, err := c.generateSeas(len(fileInfo.Fragments))
		if err != nil {
			return err
		}
		fileSeas = append(fileSeas, seas)
	}
	addresses := []string{c.GetAddress()}
	err = c.SendTransactionAndWaiting(payloads, addresses, addresses)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for i, info := range infos {
		wg.Add(1)
		go func(info map[string]interface{}, index int) {
			defer wg.Done()
			fileInfo := info["info"].(tpStorage.FileInfo)
			c.uploadFile(fileInfo, info["dst"].(string), fileSeas[index])
		}(info, i)
	}
	wg.Wait()
	return nil
}

// generate payloads for creating directory with files.
func (c *Client) generateCreateDirectoryAndFilesPayload(src, dst, keyAES string, dataShards, parShards int) ([]tpPayload.SeaStoragePayload, []map[string]interface{}, error) {
	resources, err := ioutil.ReadDir(src)
	if err != nil {
		return nil, nil, err
	}
	err = c.User.Root.CreateDirectory(dst)
	if err != nil {
		return nil, nil, err
	}

	payloads := []tpPayload.SeaStoragePayload{{
		Name:   c.Name,
		Action: tpPayload.UserCreateDirectory,
		PWD:    dst,
	}}
	infos := make([]map[string]interface{}, 0)
	for _, resource := range resources {
		if resource.IsDir() {
			dir := path.Join(dst, resource.Name()) + "/"
			err := c.User.Root.CreateDirectory(dir)
			if err != nil {
				return nil, nil, err
			}
			payloads = append(payloads, tpPayload.SeaStoragePayload{
				Name:   c.Name,
				Action: tpPayload.UserCreateDirectory,
				PWD:    dir,
			})
			payload, info, err := c.generateCreateDirectoryAndFilesPayload(path.Join(src, resource.Name()), dir, keyAES, dataShards, parShards)
			if err != nil {
				return nil, nil, err
			}
			payloads = append(payloads, payload...)
			infos = append(infos, info...)
		} else {
			info, err := crypto.GenerateFileInfo(path.Join(src, resource.Name()), c.GetPublicKey(), keyAES, dataShards, parShards)
			if err != nil {
				return nil, nil, err
			}
			err = c.User.Root.CreateFile(dst, info)
			if err != nil {
				return nil, nil, err
			}
			payloads = append(payloads, tpPayload.SeaStoragePayload{
				Name:     c.Name,
				Action:   tpPayload.UserCreateFile,
				PWD:      dst,
				FileInfo: info,
			})
			infos = append(infos, map[string]interface{}{
				"dst":  dst,
				"info": info,
			})
		}
	}
	return payloads, infos, nil
}

// CreateFile create new file of the source.
// After sending transaction, upload file into P2P network.
func (c *Client) CreateFile(src, dst string, dataShards, parShards int) error {
	if !strings.HasPrefix(src, "/") {
		return errors.New("the source path should be full path")
	}
	dst = c.fixPath(dst)
	// Check Destination Path exists
	_, err := c.User.Root.GetDirectory(dst)
	if err != nil {
		return err
	}
	keyAES := tpCrypto.GenerateRandomAESKey(lib.AESKeySize)
	info, err := crypto.GenerateFileInfo(src, c.GetPublicKey(), tpCrypto.BytesToHex(keyAES), dataShards, parShards)
	if err != nil {
		return err
	}
	err = c.User.Root.CreateFile(dst, info)
	if err != nil {
		return err
	}

	fragmentSeas, err := c.generateSeas(len(info.Fragments))
	if err != nil {
		return err
	}

	addresses := []string{c.GetAddress()}
	err = c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
		Action:   tpPayload.UserCreateFile,
		Name:     c.Name,
		PWD:      dst,
		FileInfo: info,
	}}, addresses, addresses)

	if err != nil {
		return err
	}
	c.uploadFile(info, dst, fragmentSeas)
	return nil
}

// generate the list of seas for file upload.
func (c *Client) generateSeas(fragments int) ([][]string, error) {
	seas, err := lib.ListSeasPublicKey("", lib.DefaultQueryLimit)
	if err != nil {
		return nil, err
	} else if len(seas) == 0 {
		return nil, errors.New("not enough storage resources")
	}
	fragmentSeas := make([][]string, 0)
	for i := 0; i < fragments; i++ {
		// TODO: Algorithm for select sea && user selected fragmentSeas
		peers := make([]string, 0)
		if len(seas) <= 3 {
			peers = append(peers, seas...)
		} else {
			for j := i; j <= i+len(fragmentSeas); j++ {
				peers = append(peers, seas[j%len(seas)])
				if len(peers) >= 3 {
					break
				}
			}
		}
		fragmentSeas = append(fragmentSeas, peers)
	}
	return fragmentSeas, nil
}

// uploadFile upload file into P2P network.
func (c *Client) uploadFile(fileInfo tpStorage.FileInfo, dst string, seas [][]string) {
	var wg sync.WaitGroup
	for i, fragment := range fileInfo.Fragments {
		f, subErr := os.Open(path.Join(lib.DefaultTmpPath, fileInfo.Hash, fmt.Sprintf("%s.%d", fileInfo.Hash, i)))
		if subErr != nil && os.IsNotExist(subErr) {
			continue
		}
		wg.Add(1)
		go func(src *os.File, hash string, size int64, seas []string) {
			defer func() {
				wg.Done()
				src.Close()
			}()
			c.Upload(src, dst, fileInfo.Name, hash, size, seas)
		}(f, fragment.Hash, fragment.Size, seas[i])
	}
	wg.Wait()
	err := os.RemoveAll(path.Join(lib.DefaultTmpPath, fileInfo.Hash))
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"hash": fileInfo.Hash,
		}).Warnf("failed to clean fragments: %v", err)
	}
	lib.Logger.WithFields(logrus.Fields{
		"filename": fileInfo.Name,
	}).Info("file upload finish")
}

// Rename change the target name to new name.
func (c *Client) Rename(src, newName string) error {
	p, name := c.splitPathName(src)
	err := c.User.Root.UpdateName(p, name, newName)
	if err != nil {
		return err
	}
	addresses := []string{c.GetAddress()}
	return c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
		Name:   c.Name,
		Action: tpPayload.UserUpdateName,
		PWD:    p,
		Target: []string{name, newName},
	}}, addresses, addresses)
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
func (c *Client) DeleteDirectory(p string) error {
	p, name := c.splitPathName(p)
	seaOperations, err := c.User.Root.DeleteDirectory(p, name, true)
	if err != nil {
		return err
	}
	addresses := []string{c.GetAddress()}
	for addr := range seaOperations {
		addresses = append(addresses, addr)
	}
	err = c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserDeleteDirectory,
		Name:   c.Name,
		PWD:    p,
		Target: []string{name},
	}}, addresses, addresses)
	return err
}

// DeleteFile delete the target file, then send transaction.
func (c *Client) DeleteFile(p string) error {
	p, name := c.splitPathName(p)
	seaOperations, err := c.User.Root.DeleteFile(p, name, true)
	if err != nil {
		return err
	}
	addresses := []string{c.GetAddress()}
	for addr := range seaOperations {
		addresses = append(addresses, addr)
	}
	err = c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
		Action: tpPayload.UserDeleteFile,
		Name:   c.Name,
		PWD:    p,
		Target: []string{name},
	}}, addresses, addresses)
	return err
}

// Move change the iNode's parent path from source to destination.
func (c *Client) Move(src, dst string) error {
	dst = c.fixPath(dst)
	p, name := c.splitPathName(src)
	err := c.User.Root.Move(p, name, dst)
	if err != nil {
		return err
	}
	addresses := []string{c.GetAddress()}
	return c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
		Name:   c.Name,
		Action: tpPayload.UserMove,
		PWD:    p,
		Target: []string{name, dst},
	}}, addresses, addresses)
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
		c.downloadFile(iNode.(*tpStorage.File), "", "", dst)
	case *tpStorage.Directory:
		wg := &sync.WaitGroup{}
		wg.Add(1)
		c.downloadDirectory(iNode.(*tpStorage.Directory), "", "", dst, wg)
		wg.Wait()
	}
}

// DownloadSharedFiles download the file or directory in 'shared' directory of owner to destination path in system.
func (c *Client) DownloadSharedFiles(p, dst, ownerAddr string) {
	uBytes, err := lib.GetStateData(ownerAddr)
	if err != nil {
		fmt.Println(err)
	}
	u, err := tpUser.UserFromBytes(uBytes)
	if err != nil {
		fmt.Println(err)
	}
	ownerPub := u.PublicKey
	p, name := c.splitPathName(p)
	iNode, err := u.Root.GetINode(p, name)
	if err != nil {
		fmt.Println(err)
		return
	}
	switch iNode.(type) {
	case *tpStorage.File:
		c.downloadFile(iNode.(*tpStorage.File), ownerAddr, ownerPub, dst)
	case *tpStorage.Directory:
		wg := &sync.WaitGroup{}
		wg.Add(1)
		c.downloadDirectory(iNode.(*tpStorage.Directory), ownerAddr, ownerPub, dst, wg)
		wg.Wait()
	}
}

// download files in it and recursive call to download directories in it.
func (c *Client) downloadDirectory(dir *tpStorage.Directory, ownerAddr, ownerPub, dst string, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, iNode := range dir.INodes {
		switch iNode.(type) {
		case *tpStorage.File:
			wg.Add(1)
			go func(f *tpStorage.File) {
				defer wg.Done()
				c.downloadFile(f, ownerAddr, ownerPub, path.Join(dst, dir.Name))
			}(iNode.(*tpStorage.File))
		case *tpStorage.Directory:
			wg.Add(1)
			go func(d *tpStorage.Directory) {
				c.downloadDirectory(d, ownerAddr, ownerPub, path.Join(dst, dir.Name), wg)
			}(iNode.(*tpStorage.Directory))
		}
	}
}

// download file of the target path.
func (c *Client) downloadFile(f *tpStorage.File, ownerAddr, ownerPub, dst string) {
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
		err = c.Download(storagePath, ownerPub, fragment)
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
	defer func() {
		inFile.Close()
		os.Remove(inFile.Name())
	}()
	dstFile, _ := os.OpenFile(path.Join(dst, f.Name), os.O_CREATE|os.O_WRONLY, 0644)
	defer dstFile.Close()
	var fileKey *tpStorage.FileKey
	if ownerAddr == "" {
		fileKey = c.User.Root.Keys.GetKey(f.KeyIndex)
	} else {
		oBytes, err := lib.GetStateData(ownerAddr)
		if err != nil {
			fmt.Println("failed to get owner:", err)
			return
		}
		o, err := tpUser.UserFromBytes(oBytes)
		if err != nil {
			fmt.Println("failed to unmarshal:", err)
		}
		fileKey = o.Root.Keys.GetKey(f.KeyIndex)
	}
	var key []byte
	var hash string
	if fileKey.Published {
		key = tpCrypto.HexToBytes(fileKey.Key)
	} else if ownerAddr == "" {
		key, err = c.DecryptFileKey(fileKey.Key)
		if err != nil {
			fmt.Println("failed to decrypt file key:", err)
			return
		}
	} else {
		fmt.Println("download success:", dstFile.Name())
		return
	}
	hash, err = crypto.DecryptFile(inFile, dstFile, key)
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
func (c *Client) PublishKey(p string) error {
	iNode, err := c.GetINode(p)
	if err != nil {
		return err
	}
	addresses := []string{c.GetAddress()}
	switch iNode.(type) {
	case *tpStorage.File:
		f := iNode.(*tpStorage.File)
		key, err := c.publishFileKey(f)
		if err != nil {
			return err
		}
		return c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
			Name:   c.Name,
			Action: tpPayload.UserPublishKey,
			Target: []string{f.KeyIndex},
			Key:    key}}, addresses, addresses)
	case *tpStorage.Directory:
		payloadMap, err := c.publishDirectoryKey(iNode.(*tpStorage.Directory))
		if err != nil {
			return err
		}
		payloads := make([]tpPayload.SeaStoragePayload, 0)
		for _, payload := range payloadMap {
			payloads = append(payloads, payload)
		}
		return c.SendTransactionAndWaiting(payloads, addresses, addresses)
	}
	return errors.New("failed to publish key")
}

// publish keys of the files in the directory.
func (c *Client) publishDirectoryKey(dir *tpStorage.Directory) (map[string]tpPayload.SeaStoragePayload, error) {
	payloads := make(map[string]tpPayload.SeaStoragePayload)
	for _, iNode := range dir.INodes {
		switch iNode.(type) {
		case *tpStorage.File:
			f := iNode.(*tpStorage.File)
			key, err := c.publishFileKey(f)
			if err != nil {
				return nil, err
			}
			_, ok := payloads[f.KeyIndex]
			if !ok {
				payloads[f.KeyIndex] = tpPayload.SeaStoragePayload{
					Name:   c.Name,
					Action: tpPayload.UserPublishKey,
					Target: []string{f.KeyIndex},
					Key:    key,
				}
			}
		case *tpStorage.Directory:
			subPayloads, err := c.publishDirectoryKey(iNode.(*tpStorage.Directory))
			if err != nil {
				return nil, err
			}
			for keyIndex, payload := range subPayloads {
				_, ok := payloads[keyIndex]
				if !ok {
					payloads[keyIndex] = payload
				}
			}
		}
	}
	return payloads, nil
}

// publish key of the file.
func (c *Client) publishFileKey(file *tpStorage.File) (key string, err error) {
	keyBytes, err := c.DecryptFileKey(c.User.Root.Keys.GetKey(file.KeyIndex).Key)
	if err != nil {
		return
	}
	key = tpCrypto.BytesToHex(keyBytes)
	err = c.User.Root.PublishKey(c.GetPublicKey(), file.KeyIndex, key)
	if err != nil {
		return
	}
	return key, nil
}

// ShareFiles share the files from 'home' directory to 'shared' directory.
func (c *Client) ShareFiles(src, dst string) ([]string, error) {
	dst = c.fixPath(dst)
	p, name := c.splitPathName(src)
	seaOperations, keys, err := c.User.Root.ShareFiles(p, name, dst, true)
	if err != nil {
		return nil, err
	}
	addresses := []string{c.GetAddress()}
	for addr := range seaOperations {
		addresses = append(addresses, addr)
	}
	err = c.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{{
		Name:   c.Name,
		Action: tpPayload.UserShare,
		PWD:    p,
		Target: []string{name, dst},
	}}, addresses, addresses)
	return keys, err
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
