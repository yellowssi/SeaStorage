package p2p

import (
	"errors"
	p2pCrypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	peer "github.com/libp2p/go-libp2p-peer"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpStorage "gitlab.com/SeaStorage/SeaStorage-TP/storage"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"math"
	"os"
)

type UserNode struct {
	uploadInfos   map[string]*userUploadInfo
	downloadInfos map[string]*userDownloadInfo
	*lib.ClientFramework
	*Node
	*UserUploadQueryProtocol
	*UserUploadProtocol
	*UserOperationProtocol
	*UserDownloadProtocol
}

func NewUserNode(host host.Host, cli *lib.ClientFramework) *UserNode {
	n := &UserNode{
		Node:            NewNode(host),
		ClientFramework: cli,
		uploadInfos:     make(map[string]*userUploadInfo),
		downloadInfos:   make(map[string]*userDownloadInfo),
	}
	n.UserUploadQueryProtocol = NewUserUploadQueryProtocol(n)
	n.UserUploadProtocol = NewUserUploadProtocol(n)
	n.UserOperationProtocol = NewUserOperationProtocol(n)
	n.UserDownloadProtocol = NewUserDownloadProtocol(n)
	return n
}

func (n *UserNode) Upload(src *os.File, dst, name, hash string, size int64, seas []p2pCrypto.PubKey) {
	done := make(chan bool)
	tag := tpCrypto.SHA512HexFromBytes([]byte(dst + name + hash))
	n.uploadInfos[tag] = &userUploadInfo{
		src:        src,
		packages:   int64(math.Ceil(float64(size) / float64(lib.PackageSize))),
		operations: make(map[peer.ID]*tpUser.Operation),
		done:       done,
	}
	uploadInfo := n.uploadInfos[tag]
	for _, s := range seas {
		seaId, err := peer.IDFromPublicKey(s)
		pubKeys, err := s.Bytes()
		if err != nil {
			continue
		}
		uploadInfo.lock.Lock()
		uploadInfo.operations[seaId] = n.GenerateOperation(tpCrypto.BytesToHex(pubKeys), dst, name, hash, size)
		uploadInfo.lock.Unlock()
		err = n.SendUploadQuery(seaId, tag, size)
		if err != nil {
			err = n.SendUploadQuery(seaId, tag, size)
			if err != nil {
				uploadInfo.lock.Lock()
				delete(uploadInfo.operations, seaId)
				uploadInfo.lock.Unlock()
				continue
			}
		}
	}
	go func() {
		if len(uploadInfo.operations) == 0 {
			done <- true
		}
	}()
	<-done
	lib.Logger.WithFields(logrus.Fields{
		"tag": tag,
	}).Info("upload finish")
	delete(n.uploadInfos, tag)
}

func (n *UserNode) Download(dst string, fragment *tpStorage.Fragment) error {
	for _, s := range fragment.Seas {
		publicKey, err := p2pCrypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(s.PublicKey))
		if err != nil {
			continue
		}
		peerId, err := peer.IDFromPublicKey(publicKey)
		if err != nil {
			continue
		}
		err = n.SendDownloadProtocol(peerId, dst, fragment.Hash, fragment.Size)
		if err == nil {
			return nil
		}
	}
	return errors.New("failed to download fragment")
}
