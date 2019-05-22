package p2p

import (
	"errors"
	crypto "github.com/libp2p/go-libp2p-crypto"
	"gitlab.com/SeaStorage/SeaStorage-TP/storage"
	"math"
	"os"

	"github.com/deckarep/golang-set"
	host "github.com/libp2p/go-libp2p-host"
	peer "github.com/libp2p/go-libp2p-peer"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

type UserNode struct {
	seas map[string]mapset.Set
	*Node
	*UserUploadQueryProtocol
	*UserUploadProtocol
	*UserOperationProtocol
	*UserDownloadProtocol
}

func NewUserNode(host host.Host) *UserNode {
	n := &UserNode{Node: NewNode(host), seas: make(map[string]mapset.Set)}
	n.UserUploadQueryProtocol = NewUserUploadQueryProtocol(n)
	n.UserUploadProtocol = NewUserUploadProtocol(n)
	n.UserOperationProtocol = NewUserOperationProtocol(n)
	n.UserDownloadProtocol = NewUserDownloadProtocol(n)
	return n
}

func (n *UserNode) UploadFile(src *os.File, operation *tpUser.Operation, seas []peer.ID) error {
	done := make(chan bool)
	tag := tpCrypto.SHA512HexFromBytes([]byte(operation.Path + operation.Name))
	n.operations[tag] = operation
	n.srcs[tag] = src
	n.packages[tag] = int64(math.Ceil(float64(operation.Size) / float64(lib.PackageSize)))
	n.dones[tag] = done
	n.seas[tag] = mapset.NewSet()
	for _, s := range seas {
		err := n.SendUploadQuery(s, operation.Path, operation.Name, operation.Size)
		if err != nil {
			err = n.SendUploadQuery(s, operation.Path, operation.Name, operation.Size)
			if err != nil {
				continue
			}
		}
		n.seas[tag].Add(s)
	}
	<-done
	delete(n.srcs, tag)
	delete(n.packages, tag)
	delete(n.dones, tag)
	delete(n.operations, tag)
	return nil
}

func (n *UserNode) DownloadFragment(dst string, fragment *storage.Fragment) error {
	for _, s := range fragment.Seas {
		publicKey, err := crypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(s.PublicKey))
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
