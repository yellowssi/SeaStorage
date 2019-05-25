package p2p

import (
	"errors"
	"os"
	"path/filepath"

	p2pHost "github.com/libp2p/go-libp2p-host"
	p2pPeer "github.com/libp2p/go-libp2p-peer"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

type SeaNode struct {
	*lib.ClientFramework
	storagePath   string
	size          int64
	freeSize      int64
	uploadInfos   map[p2pPeer.ID]map[string]*seaUploadInfo
	downloadInfos map[p2pPeer.ID]map[string]*seaDownloadInfo
	*Node
	*SeaUploadQueryProtocol
	*SeaUploadProtocol
	*SeaOperationProtocol
	*SeaDownloadProtocol
	*SeaDownloadConfirmProtocol
}

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
		uploadInfos:     make(map[p2pPeer.ID]map[string]*seaUploadInfo),
		downloadInfos:   make(map[p2pPeer.ID]map[string]*seaDownloadInfo),
	}
	seaNode.SeaUploadQueryProtocol = NewSeaUploadQueryProtocol(seaNode)
	seaNode.SeaUploadProtocol = NewSeaUploadProtocol(seaNode)
	seaNode.SeaOperationProtocol = NewSeaOperationProtocol(seaNode)
	seaNode.SeaDownloadProtocol = NewSeaDownloadProtocol(seaNode)
	seaNode.SeaDownloadConfirmProtocol = NewSeaDownloadConfirmProtocol(seaNode)
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
