package p2p

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/sawtooth-sdk-go/signing"
	"github.com/libp2p/go-libp2p"
	p2pCrypto "github.com/libp2p/go-libp2p-crypto"
	ma "github.com/multiformats/go-multiaddr"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

type SeaNode struct {
	*lib.ClientFramework
	storagePath string
	size        int64
	freeSize    int64
	signer      *signing.Signer
	*Node
	*SeaUploadQueryProtocol
	*SeaUploadProtocol
	*SeaOperationProtocol
	*SeaDownloadProtocol
}

func NewSeaNode(c *lib.ClientFramework, storagePath string, size int64, listenAddress string, port int, priv []byte) (*SeaNode, error) {
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
			return nil, errors.New("the storage size is not enough")
		}
		freeSize = size - totalSize
	}
	privateKey, err := p2pCrypto.UnmarshalSecp256k1PrivateKey(priv)
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
		ClientFramework: c,
		storagePath:     storagePath,
		size:            size,
		freeSize:        freeSize,
		signer:          signer,
		Node:            NewNode(host),
	}
	seaNode.SeaUploadQueryProtocol = NewSeaUploadQueryProtocol(seaNode)
	seaNode.SeaUploadProtocol = NewSeaUploadProtocol(seaNode)
	seaNode.SeaOperationProtocol = NewSeaOperationProtocol(seaNode)
	seaNode.SeaDownloadProtocol = NewSeaDownloadProtocol(seaNode)
	return seaNode, nil
}

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
