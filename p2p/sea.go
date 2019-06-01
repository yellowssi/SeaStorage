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

package p2p

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	p2pHost "github.com/libp2p/go-libp2p-core/host"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/sirupsen/logrus"
	tpPayload "gitlab.com/SeaStorage/SeaStorage-TP/payload"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

// SeaNode is the P2P network node for sea providing storage.
type SeaNode struct {
	*lib.ClientFramework
	storagePath string
	size        int64
	freeSize    int64
	operations  struct {
		sync.RWMutex
		m map[string]tpUser.Operation
	}
	uploadInfos struct {
		sync.RWMutex
		m map[p2pPeer.ID]map[string]*seaUploadInfo
	}
	downloadInfos struct {
		sync.RWMutex
		m map[p2pPeer.ID]map[string]*seaDownloadInfo
	}
	*Node
	*SeaUploadQueryProtocol
	*SeaUploadProtocol
	*SeaOperationProtocol
	*SeaDownloadProtocol
	*SeaDownloadConfirmProtocol
}

// NewSeaNode is the construct for SeaNode.
func NewSeaNode(c *lib.ClientFramework, storagePath string, size int64, host p2pHost.Host) (*SeaNode, error) {
	freeSize := size
	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		err = os.MkdirAll(storagePath, 0755)
		if err != nil {
			return nil, err
		}
	} else {
		totalSize, err := dirSize(storagePath)
		if err != nil {
			return nil, err
		}
		if totalSize > size {
			return nil, errors.New("the storage pubSize is not enough")
		}
		freeSize = size - totalSize
	}
	seaNode := &SeaNode{
		ClientFramework: c,
		storagePath:     storagePath,
		size:            size,
		freeSize:        freeSize,
		Node:            NewNode(host),
		operations: struct {
			sync.RWMutex
			m map[string]tpUser.Operation
		}{m: make(map[string]tpUser.Operation)},
		uploadInfos: struct {
			sync.RWMutex
			m map[p2pPeer.ID]map[string]*seaUploadInfo
		}{m: make(map[p2pPeer.ID]map[string]*seaUploadInfo)},
		downloadInfos: struct {
			sync.RWMutex
			m map[p2pPeer.ID]map[string]*seaDownloadInfo
		}{m: make(map[p2pPeer.ID]map[string]*seaDownloadInfo)},
	}
	seaNode.SeaUploadQueryProtocol = NewSeaUploadQueryProtocol(seaNode)
	seaNode.SeaUploadProtocol = NewSeaUploadProtocol(seaNode)
	seaNode.SeaOperationProtocol = NewSeaOperationProtocol(seaNode)
	seaNode.SeaDownloadProtocol = NewSeaDownloadProtocol(seaNode)
	seaNode.SeaDownloadConfirmProtocol = NewSeaDownloadConfirmProtocol(seaNode)
	go func() {
		for {
			time.Sleep(time.Minute)
			seaNode.SendUserOperations()
		}
	}()
	return seaNode, nil
}

// SendUserOperations send users' operations for transaction.
func (s *SeaNode) SendUserOperations() {
	s.operations.Lock()
	length := len(s.operations.m)
	s.operations.Unlock()
	if length > 0 {
		hashes := make([]string, 0)
		operations := make([]tpUser.Operation, 0)
		s.operations.Lock()
		for hash, operation := range s.operations.m {
			hashes = append(hashes, hash)
			operations = append(operations, operation)
		}
		s.operations.Unlock()
		payload := tpPayload.SeaStoragePayload{
			Name:           s.Name,
			Action:         tpPayload.SeaStoreFile,
			UserOperations: operations,
		}
		addresses := []string{s.GetAddress()}
	L:
		for _, operation := range operations {
			for _, addr := range addresses {
				if operation.Address == addr {
					continue L
				}
			}
			addresses = append(addresses, operation.Address)
		}
		resp, err := s.SendTransaction([]tpPayload.SeaStoragePayload{payload}, addresses, addresses, lib.DefaultWait)
		if err != nil {
			resp, err = s.SendTransaction([]tpPayload.SeaStoragePayload{payload}, addresses, addresses, lib.DefaultWait)
			if err != nil {
				lib.Logger.Error("failed to send transactions")
			}
		} else {
			lib.Logger.WithFields(logrus.Fields{
				"response": resp,
			}).Info("send transaction success")
			s.operations.Lock()
			for _, hash := range hashes {
				delete(s.operations.m, hash)
			}
			s.operations.Unlock()
		}
	}
}

// get the total size of directory.
func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}
