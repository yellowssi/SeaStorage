package p2p

import (
	"github.com/gogo/protobuf/proto"
	crypto "github.com/libp2p/go-libp2p-crypto"
	host "github.com/libp2p/go-libp2p-host"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
)

type Node struct {
	host.Host
	*UploadProtocol
	*DownloadProtocol
}

func NewNode(host host.Host, done chan bool) *Node {
	node := &Node{Host: host}
	node.UploadProtocol = NewUploadProtocol(node, done)
	node.DownloadProtocol = NewDownloadProtocol(node, done)
	return node
}

func (n *Node) authenticateMessage(message proto.Message, signature *tpUser.Operation) bool {
	bytes, err := proto.Marshal(message)
	if err != nil {
		logrus.Debug("failed to marshal pb message")
		return false
	}

	pub, err := crypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(signature.PublicKey))
	if err != nil {
		logrus.Debug("failed to extract key from message")
		return false
	}


}
