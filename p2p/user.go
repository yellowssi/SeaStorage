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
	"context"
	"errors"
	p2pDHT "github.com/libp2p/go-libp2p-kad-dht"
	"math"
	"os"
	"sync"

	p2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
	p2pHost "github.com/libp2p/go-libp2p-core/host"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/sirupsen/logrus"
	tpCrypto "github.com/yellowssi/SeaStorage-TP/crypto"
	tpStorage "github.com/yellowssi/SeaStorage-TP/storage"
	tpUser "github.com/yellowssi/SeaStorage-TP/user"
	"github.com/yellowssi/SeaStorage/lib"
)

// UserNode is the P2P network node for user upload and download file.
type UserNode struct {
	uploadInfos struct {
		sync.RWMutex
		m map[string]*userUploadInfo
	}
	downloadInfos struct {
		sync.RWMutex
		m map[string]*userDownloadInfo
	}
	*lib.ClientFramework
	*Node
	*UserUploadQueryProtocol
	*UserUploadProtocol
	*UserOperationProtocol
	*UserDownloadProtocol
}

// NewUserNode is the construct for UserNode.
func NewUserNode(ctx context.Context, host p2pHost.Host, kadDHT *p2pDHT.IpfsDHT, cli *lib.ClientFramework) *UserNode {
	n := &UserNode{
		Node:            NewNode(ctx, host, kadDHT),
		ClientFramework: cli,
		uploadInfos: struct {
			sync.RWMutex
			m map[string]*userUploadInfo
		}{m: make(map[string]*userUploadInfo)},
		downloadInfos: struct {
			sync.RWMutex
			m map[string]*userDownloadInfo
		}{m: make(map[string]*userDownloadInfo)},
	}
	n.UserUploadQueryProtocol = NewUserUploadQueryProtocol(n)
	n.UserUploadProtocol = NewUserUploadProtocol(n)
	n.UserOperationProtocol = NewUserOperationProtocol(n)
	n.UserDownloadProtocol = NewUserDownloadProtocol(n)
	return n
}

// Upload start upload file process. Firstly, generate information of source file.
// After information generated, it will be stored for data transport.
// Then start upload file process by sending upload query request protobuf.
func (n *UserNode) Upload(src *os.File, dst, name, hash string, size int64, seas []string) {
	done := make(chan bool)
	tag := tpCrypto.SHA512HexFromBytes([]byte(dst + name + hash))
	uploadInfo := &userUploadInfo{
		src:        src,
		packages:   int64(math.Ceil(float64(size) / float64(lib.PackageSize))),
		operations: make(map[p2pPeer.ID]*tpUser.Operation),
		done:       done,
	}
	seaIDs := make([]p2pPeer.ID, 0)
	for _, s := range seas {
		seaPub, err := p2pCrypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(s))
		if err != nil {
			continue
		}
		seaID, err := p2pPeer.IDFromPublicKey(seaPub)
		if err != nil {
			continue
		}
		seaIDs = append(seaIDs, seaID)
		uploadInfo.operations[seaID] = n.GenerateOperation(s, dst, name, hash, size)
	}
	n.uploadInfos.Lock()
	n.uploadInfos.m[tag] = uploadInfo
	n.uploadInfos.Unlock()
	for _, seaID := range seaIDs {
		err := n.SendUploadQuery(seaID, tag, size)
		if err != nil {
			delete(uploadInfo.operations, seaID)
			continue
		}
	}
	go func(info *userUploadInfo) {
		uploadInfo.Lock()
		if len(uploadInfo.operations) == 0 {
			done <- true
		}
		uploadInfo.Unlock()
	}(uploadInfo)
	<-done
	lib.Logger.WithFields(logrus.Fields{
		"tag": tag,
	}).Info("fragment upload finish")
	n.uploadInfos.Lock()
	delete(n.uploadInfos.m, tag)
	n.uploadInfos.Unlock()
}

// Download start download file process. Firstly, generate information for downloaded file.
// Send download request to start download process. After download finished, the downloaded
// file will be verify by stored information.
func (n *UserNode) Download(dst, owner string, fragment *tpStorage.Fragment) error {
	for _, s := range fragment.Seas {
		publicKey, err := p2pCrypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(s.PublicKey))
		if err != nil {
			continue
		}
		peerID, err := p2pPeer.IDFromPublicKey(publicKey)
		if err != nil {
			continue
		}
		err = n.SendDownloadProtocol(peerID, dst, owner, fragment.Hash, fragment.Size)
		if err == nil {
			return nil
		}
	}
	return errors.New("failed to download fragment")
}
