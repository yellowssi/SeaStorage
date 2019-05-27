package p2p

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	p2pHost "github.com/libp2p/go-libp2p-core/host"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/sirupsen/logrus"
	tpPayload "gitlab.com/SeaStorage/SeaStorage-TP/payload"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

type SeaNode struct {
	*lib.ClientFramework
	storagePath string
	size        int64
	freeSize    int64
	operations  struct {
		sync.RWMutex
		m map[string]tpUser.Operation
	}
	uploadInfos struct {
		sync.RWMutex
		m map[p2pPeer.ID]map[string]*seaUploadInfo
	}
	downloadInfos struct {
		sync.RWMutex
		m map[p2pPeer.ID]map[string]*seaDownloadInfo
	}
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
		operations: struct {
			sync.RWMutex
			m map[string]tpUser.Operation
		}{m: make(map[string]tpUser.Operation)},
		uploadInfos: struct {
			sync.RWMutex
			m map[p2pPeer.ID]map[string]*seaUploadInfo
		}{m: make(map[p2pPeer.ID]map[string]*seaUploadInfo)},
		downloadInfos: struct {
			sync.RWMutex
			m map[p2pPeer.ID]map[string]*seaDownloadInfo
		}{m: make(map[p2pPeer.ID]map[string]*seaDownloadInfo)},
	}
	seaNode.SeaUploadQueryProtocol = NewSeaUploadQueryProtocol(seaNode)
	seaNode.SeaUploadProtocol = NewSeaUploadProtocol(seaNode)
	seaNode.SeaOperationProtocol = NewSeaOperationProtocol(seaNode)
	seaNode.SeaDownloadProtocol = NewSeaDownloadProtocol(seaNode)
	seaNode.SeaDownloadConfirmProtocol = NewSeaDownloadConfirmProtocol(seaNode)
	go seaNode.SendOperations()
	return seaNode, nil
}

func (s *SeaNode) SendOperations() {
	for {
		time.Sleep(time.Minute)
		s.operations.Lock()
		length := len(s.operations.m)
		s.operations.Unlock()
		if length > 0 {
			hashes := make([]string, 0)
			operations := make([]tpUser.Operation, 0)
			s.operations.Lock()
			for hash, operation := range s.operations.m {
				hashes = append(hashes, hash)
				operations = append(operations, operation)
			}
			s.operations.Unlock()
			payload := tpPayload.SeaStoragePayload{
				Name:       s.Name,
				Action:     tpPayload.SeaStoreFile,
				Operations: operations,
			}
			resp, err := s.SendTransaction([]tpPayload.SeaStoragePayload{payload}, lib.DefaultWait)
			if err != nil {
				resp, err = s.SendTransaction([]tpPayload.SeaStoragePayload{payload}, lib.DefaultWait)
				if err != nil {
					lib.Logger.Error("failed to send transactions")
				}
			} else {
				lib.Logger.WithFields(logrus.Fields{
					"response": resp,
				}).Info("send transaction success")
				s.operations.Lock()
				for _, hash := range hashes {
					delete(s.operations.m, hash)
				}
				s.operations.Unlock()
			}
		}
	}
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
