package p2p

import (
	"context"
	"errors"
	"fmt"
	"github.com/hyperledger/sawtooth-sdk-go/signing"
	"github.com/libp2p/go-libp2p"
	crypto "github.com/libp2p/go-libp2p-crypto"
	ma "github.com/multiformats/go-multiaddr"
	tpStat "gitlab.com/SeaStorage/SeaStorage-TP/state"
	"os"
	"syscall"
)

type SeaNode struct {
	Name        string
	size        int
	storagePath string
	freeSize    int
	signer      *signing.Signer
	*Node
	*SeaUploadQueryProtocol
	*SeaUploadProtocol
	*SeaDownloadProtocol
}

func NewSeaNode(name, listenAddress string, priv []byte, port int) (*SeaNode, error) {
	privateKey, err := crypto.UnmarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	listen, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", listenAddress, port))
	if err != nil {
		return nil, err
	}
	host, err := libp2p.New(context.Background(), libp2p.ListenAddrs(listen), libp2p.Identity(privateKey))
	if err != nil {
		return nil, err
	}
	privKey := signing.NewSecp256k1PrivateKey(priv)
	cryptoFactory := signing.NewCryptoFactory(signing.NewSecp256k1Context())
	signer := cryptoFactory.NewSigner(privKey)
	seaNode := &SeaNode{
		Name:   name,
		signer: signer,
		Node:   NewNode(host),
	}
	seaNode.SeaUploadQueryProtocol = NewSeaUploadQueryProtocol(seaNode)
	seaNode.SeaUploadProtocol = NewSeaUploadProtocol(seaNode)
	seaNode.SeaDownloadProtocol = NewSeaDownloadProtocol(seaNode)
	return seaNode, nil
}

func (s *SeaNode) SetStoragePath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	s.storagePath = path
	return nil
}

func (s *SeaNode) SetSize(size int) error {
	if size < s.size-s.freeSize {
		return errors.New("storage is not enough for storing files")
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	var stat syscall.Statfs_t
	err = syscall.Statfs(wd, &stat)
	if err != nil {
		return err
	}
	if size > int(stat.Bavail*uint64(stat.Bsize)) {
		return errors.New("disk has no enough spaces for storage")
	}
	s.freeSize = size - s.size + s.freeSize
	s.size = size
	return nil
}

func (s *SeaNode) GetAddress() string {
	return tpStat.MakeAddress(tpStat.AddressTypeSea, s.Name, s.signer.GetPublicKey().AsHex())
}
