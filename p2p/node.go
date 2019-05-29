package p2p

import (
	"context"
	"log"
	"time"

	"github.com/btcsuite/btcd/btcec"
	ggio "github.com/gogo/protobuf/io"
	"github.com/gogo/protobuf/proto"
	p2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
	p2pHelpers "github.com/libp2p/go-libp2p-core/helpers"
	p2pHost "github.com/libp2p/go-libp2p-core/host"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	p2pProtocol "github.com/libp2p/go-libp2p-core/protocol"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p/pb"
)

type Node struct {
	p2pHost.Host
}

func NewNode(host p2pHost.Host) *Node {
	return &Node{Host: host}
}

// Authenticate incoming p2p message
// message: a protobufs go data object
// data: common p2p message data
func (n *Node) authenticateMessage(message proto.Message, data *pb.MessageData) bool {
	// store a temp ref to signature and remove it from message data
	// sign is a string to allow easy reset to zero-value (empty string)
	sign := data.Sign
	data.Sign = nil

	// marshall data without the signature to protobufs3 binary format
	bin, err := proto.Marshal(message)
	if err != nil {
		log.Println(err, "failed to marshal pb message")
		return false
	}

	// restore sig in message data (for possible future use)
	data.Sign = sign

	// restore p2pPeer id binary format from base58 encoded node id data
	peerId, err := p2pPeer.IDHexDecode(data.NodeId)
	if err != nil {
		log.Println(err, "Failed to decode node id from base58")
		return false
	}

	// verify the data was authored by the signing p2pPeer identified by the public key
	// and signature included in the message
	return n.verifyData(bin, []byte(sign), peerId, data.NodePubKey)
}

// sign an outgoing p2p message payload
func (n *Node) signProtoMessage(message proto.Message) ([]byte, error) {
	data, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	return n.signData(data)
}

// sign binary data using the local node's private key
func (n *Node) signData(data []byte) ([]byte, error) {
	key := n.Peerstore().PrivKey(n.ID())
	res, err := key.Sign(data)
	return res, err
}

// Verify incoming p2p message data integrity
// data: data to verify
// signature: author signature provided in the message payload
// peerId: author p2pPeer id from the message payload
// pubKeyData: author public key from the message payload
func (n *Node) verifyData(data []byte, signature []byte, peerId p2pPeer.ID, pubKeyData []byte) bool {
	key, err := p2pCrypto.UnmarshalSecp256k1PublicKey(pubKeyData)
	if err != nil {
		log.Println(err, "Failed to extract key from message key data")
		return false
	}

	// extract node id from the provided public key
	idFromKey, err := p2pPeer.IDFromPublicKey(key)

	if err != nil {
		log.Println(err, "Failed to extract p2pPeer id from public key")
		return false
	}

	// verify that message author node id matches the provided node public key
	if idFromKey != peerId {
		log.Println(err, "Node id and provided public key mismatch")
		return false
	}

	res, err := key.Verify(data, signature)
	if err != nil {
		log.Println(err, "Error authenticating data")
		return false
	}

	return res
}

// helper method - generate message data shared between all node's p2p protocols
// messageId: unique for requests, copied from request for responses
func (n *Node) NewMessageData(messageId string, gossip bool) *pb.MessageData {
	// Add protobufs bin data for message author public key
	// this is useful for authenticating  messages forwarded by a node authored by another node
	nodePubKey := (*btcec.PublicKey)(n.Peerstore().PubKey(n.ID()).(*p2pCrypto.Secp256k1PublicKey)).SerializeCompressed()

	return &pb.MessageData{
		ClientVersion: lib.FamilyName + "/" + lib.FamilyVersion,
		NodeId:        p2pPeer.IDHexEncode(n.ID()),
		NodePubKey:    nodePubKey,
		Timestamp:     time.Now().Unix(),
		Id:            messageId,
		Gossip:        gossip,
	}
}

// helper method - writes a protobuf go data object to a network stream
// data: reference of protobuf go data object to send (not the object itself)
// s: network stream to write the data to
func (n *Node) sendProtoMessage(id p2pPeer.ID, p p2pProtocol.ID, data proto.Message) bool {
	s, err := n.NewStream(context.Background(), id, p)
	if err != nil {
		log.Println(err)
		return false
	}
	writer := ggio.NewFullWriter(s)
	err = writer.WriteMsg(data)
	if err != nil {
		log.Println(err)
		s.Reset()
		return false
	}
	// FullClose closes the stream and waits for the other side to close their half.
	err = p2pHelpers.FullClose(s)
	if err != nil {
		log.Println(err)
		s.Reset()
		return false
	}
	return true
}
