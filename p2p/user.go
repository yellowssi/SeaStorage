package p2p

import (
	"errors"
	"math"
	"os"

	"github.com/deckarep/golang-set"
	p2pCrypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	peer "github.com/libp2p/go-libp2p-peer"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpStorage "gitlab.com/SeaStorage/SeaStorage-TP/storage"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

type UserNode struct {
	seas map[string]mapset.Set
	*lib.ClientFramework
	*Node
	*UserUploadQueryProtocol
	*UserUploadProtocol
	*UserOperationProtocol
	*UserDownloadProtocol
}

func NewUserNode(host host.Host, cli *lib.ClientFramework) *UserNode {
	n := &UserNode{Node: NewNode(host), ClientFramework: cli, seas: make(map[string]mapset.Set)}
	n.UserUploadQueryProtocol = NewUserUploadQueryProtocol(n)
	n.UserUploadProtocol = NewUserUploadProtocol(n)
	n.UserOperationProtocol = NewUserOperationProtocol(n)
	n.UserDownloadProtocol = NewUserDownloadProtocol(n)
	return n
}

func (n *UserNode) Upload(src *os.File, dst, name, hash string, size int64, seas []p2pCrypto.PubKey) error {
	done := make(chan bool)
	tag := tpCrypto.SHA512HexFromBytes([]byte(dst + name + hash))
	n.operations[tag] = make(map[peer.ID]*tpUser.Operation)
	n.srcs[tag] = src
	n.packages[tag] = int64(math.Ceil(float64(size) / float64(lib.PackageSize)))
	n.dones[tag] = done
	n.seas[tag] = mapset.NewSet()
	for _, s := range seas {
		seaId, err := peer.IDFromPublicKey(s)
		pubKeys, err := s.Bytes()
		if err != nil {
			continue
		}
		n.operations[tag][seaId] = n.GenerateOperation(tpCrypto.BytesToHex(pubKeys), dst, name, hash, size)
		n.seas[tag].Add(seaId)
		err = n.SendUploadQuery(seaId, tag, size)
		if err != nil {
			err = n.SendUploadQuery(seaId, tag, size)
			if err != nil {
				n.seas[tag].Remove(seaId)
				continue
			}
		}
	}
	go func() {
		if len(n.seas[tag].ToSlice()) == 0 {
			done <- true
		}
	}()
	<-done
	lib.Logger.WithFields(logrus.Fields{
		"tag": tag,
	}).Info("upload finish")
	delete(n.srcs, tag)
	delete(n.packages, tag)
	delete(n.dones, tag)
	delete(n.operations, tag)
	return nil
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
