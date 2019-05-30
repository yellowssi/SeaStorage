package p2p

import (
	"errors"
	"math"
	"os"
	"sync"

	p2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
	p2pHost "github.com/libp2p/go-libp2p-core/host"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpStorage "gitlab.com/SeaStorage/SeaStorage-TP/storage"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

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

func NewUserNode(host p2pHost.Host, cli *lib.ClientFramework) *UserNode {
	n := &UserNode{
		Node:            NewNode(host),
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

func (n *UserNode) Upload(src *os.File, dst, name, hash string, size int64, seas []string) {
	done := make(chan bool)
	tag := tpCrypto.SHA512HexFromBytes([]byte(dst + name + hash))
	uploadInfo := &userUploadInfo{
		src:        src,
		packages:   int64(math.Ceil(float64(size) / float64(lib.PackageSize))),
		operations: make(map[p2pPeer.ID]*tpUser.Operation),
		done:       done,
	}
	seaIds := make([]p2pPeer.ID, 0)
	for _, s := range seas {
		seaPub, err := p2pCrypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(s))
		if err != nil {
			continue
		}
		seaId, err := p2pPeer.IDFromPublicKey(seaPub)
		if err != nil {
			continue
		}
		seaIds = append(seaIds, seaId)
		uploadInfo.operations[seaId] = n.GenerateOperation(s, dst, name, hash, size)
	}
	n.uploadInfos.Lock()
	n.uploadInfos.m[tag] = uploadInfo
	n.uploadInfos.Unlock()
	for _, seaId := range seaIds {
		err := n.SendUploadQuery(seaId, tag, size)
		if err != nil {
			err = n.SendUploadQuery(seaId, tag, size)
			if err != nil {
				delete(uploadInfo.operations, seaId)
				continue
			}
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

func (n *UserNode) Download(dst, owner string, fragment *tpStorage.Fragment) error {
	for _, s := range fragment.Seas {
		publicKey, err := p2pCrypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(s.PublicKey))
		if err != nil {
			continue
		}
		peerId, err := p2pPeer.IDFromPublicKey(publicKey)
		if err != nil {
			continue
		}
		err = n.SendDownloadProtocol(peerId, dst, owner, fragment.Hash, fragment.Size)
		if err == nil {
			return nil
		}
	}
	return errors.New("failed to download fragment")
}
