// Copyright © 2019 yellowsea <hh1271941291@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package p2p

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	p2pNet "github.com/libp2p/go-libp2p-core/network"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p/pb"
)

const (
	downloadRequest  = "/SeaStorage/download/request/1.0.0"
	downloadResponse = "/SeaStorage/download/response/1.0.0"
	downloadConfirm  = "/SeaStorage/download/confirm/1.0.0"
)

// seaDownloadInfo is used for tag of user download request.
type seaDownloadInfo struct {
	src      *os.File
	packages int64
}

// SeaDownloadProtocol provides listener for download request protobuf and sending download response protobuf.
type SeaDownloadProtocol struct {
	node *SeaNode
}

// NewSeaDownloadProtocol is the construct for SeaDownloadProtocol.
func NewSeaDownloadProtocol(node *SeaNode) *SeaDownloadProtocol {
	p := &SeaDownloadProtocol{
		node: node,
	}
	node.SetStreamHandler(downloadRequest, p.onDownloadRequest)
	return p
}

// onDownloadRequest listen for the download request protobuf.
func (p *SeaDownloadProtocol) onDownloadRequest(s p2pNet.Stream) {
	data := &pb.DownloadRequest{}
	buf, err := ioutil.ReadAll(s)
	if err != nil {
		s.Reset()
		lib.Logger.Error(err)
		return
	}
	s.Close()

	err = proto.Unmarshal(buf, data)
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	lib.Logger.WithFields(logrus.Fields{
		"type": "download response",
		"from": s.Conn().RemotePeer().String(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download response",
			"from": s.Conn().RemotePeer().String(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	err = p.sendDownload(s.Conn().RemotePeer(), data.MessageData.Id, tpCrypto.BytesToHex(data.MessageData.NodePubKey), data.Owner, data.Hash)
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download request",
			"from": s.Conn().RemotePeer().String(),
			"data": data.String(),
		}).Warn("invalid download request or failed to send response")
	} else {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download request",
			"from": s.Conn().RemotePeer().String(),
			"data": data.String(),
		}).Info("sent response success")
	}
}

// sendDownload begin to send file.
func (p *SeaDownloadProtocol) sendDownload(peerID p2pPeer.ID, messageID, peerPub, owner, hash string) error {
	var filename string
	if owner != "" {
		filename = path.Join(p.node.storagePath, owner, "shared", hash)
	} else {
		filename = path.Join(p.node.storagePath, peerPub, "home", hash)
	}
	src, err := os.Open(filename)
	if err != nil {
		return err
	}
	stat, err := src.Stat()
	if err != nil {
		return err
	}
	packages := int64(math.Ceil(float64(stat.Size()) / float64(lib.PackageSize)))
	p.node.downloadInfos.Lock()
	peerSrcs, ok := p.node.downloadInfos.m[peerID]
	if ok {
		peerSrcs[hash] = &seaDownloadInfo{
			src:      src,
			packages: packages,
		}
	} else {
		p.node.downloadInfos.m[peerID] = map[string]*seaDownloadInfo{hash: {
			src:      src,
			packages: packages,
		}}
	}
	p.node.downloadInfos.Unlock()
	succeed := int64(0)
	for i := int64(0); i <= packages; i++ {
		err = p.sendPackage(peerID, messageID, peerPub, hash, i)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"type":      "download response",
				"to":        peerID,
				"hash":      hash,
				"packageId": i,
			}).Errorf("failed to sent protobuf: %v", err)
		} else {
			lib.Logger.WithFields(logrus.Fields{
				"type":      "download response",
				"to":        peerID,
				"hash":      hash,
				"packageId": i,
			}).Info("sent success")
			succeed++
		}
	}
	if succeed != packages {
		return errors.New("failed to send packages")
	}
	return nil
}

// sendPackage send the packages of file.
func (p *SeaDownloadProtocol) sendPackage(peerID p2pPeer.ID, messageID, peerPub, hash string, id int64) error {
	var req *pb.DownloadResponse
	p.node.downloadInfos.Lock()
	downloadInfo := p.node.downloadInfos.m[peerID][hash]
	p.node.downloadInfos.Unlock()
	if id == downloadInfo.packages {
		req = &pb.DownloadResponse{
			MessageData: p.node.NewMessageData(messageID, true),
			PackageId:   id,
			Hash:        hash,
			Data:        nil,
		}
	} else {
		buf := make([]byte, lib.PackageSize)
		n, err := downloadInfo.src.ReadAt(buf, id*lib.PackageSize)
		if err != nil && err != io.EOF {
			return err
		}
		req = &pb.DownloadResponse{
			MessageData: p.node.NewMessageData(messageID, true),
			PackageId:   id,
			Hash:        hash,
			Data:        buf[:n],
		}
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerID, downloadResponse, req)
	if !ok {
		return errors.New("failed to send proto message")
	}
	return nil
}

// SeaDownloadConfirmProtocol provides listener for download confirm protobuf.
type SeaDownloadConfirmProtocol struct {
	node *SeaNode
}

// NewSeaDownloadConfirmProtocol is the construct for SeaDownloadConfirmProtocol
func NewSeaDownloadConfirmProtocol(node *SeaNode) *SeaDownloadConfirmProtocol {
	p := &SeaDownloadConfirmProtocol{node: node}
	node.SetStreamHandler(downloadConfirm, p.onDownloadConfirm)
	return p
}

// onDownloadConfirm listen for the download confirm protocol.
func (p *SeaDownloadConfirmProtocol) onDownloadConfirm(s p2pNet.Stream) {
	data := &pb.DownloadConfirm{}
	buf, err := ioutil.ReadAll(s)
	if err != nil {
		s.Reset()
		lib.Logger.Error(err)
		return
	}
	s.Close()

	err = proto.Unmarshal(buf, data)
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	lib.Logger.WithFields(logrus.Fields{
		"type": "download confirm",
		"from": s.Conn().RemotePeer().String(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download confirm",
			"from": s.Conn().RemotePeer().String(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	p.node.downloadInfos.Lock()
	downloadInfo, ok := p.node.downloadInfos.m[s.Conn().RemotePeer()][data.Hash]
	p.node.downloadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download confirm",
			"from": s.Conn().RemotePeer().String(),
			"data": data.String(),
		}).Warn("invalid protocol")
		return
	}

	if data.PackageId == downloadInfo.packages {
		p.node.downloadInfos.Lock()
		delete(p.node.downloadInfos.m[s.Conn().RemotePeer()], data.Hash)
		p.node.downloadInfos.Unlock()
		lib.Logger.WithFields(logrus.Fields{
			"type": "download confirm",
			"from": s.Conn().RemotePeer().String(),
			"data": data.String(),
		}).Info("download success")
	} else {
		peerPub := tpCrypto.BytesToHex(data.MessageData.NodePubKey)
		err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, peerPub, data.Hash, data.PackageId)
		if err != nil {
			err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, peerPub, data.Hash, data.PackageId)
			if err != nil {
				lib.Logger.Error("failed to send package")
				return
			}
		}
	}
}

// userDownloadInfo is used for tag for user download request
type userDownloadInfo struct {
	sync.RWMutex
	downloading int
	dst         string
	size        int64
	done        chan error
}

// UserDownloadProtocol provides sending download request protobuf and listener for download response protobuf.
type UserDownloadProtocol struct {
	node *UserNode
}

// NewUserDownloadProtocol is the construct for UserDownloadProtocol
func NewUserDownloadProtocol(node *UserNode) *UserDownloadProtocol {
	d := &UserDownloadProtocol{
		node: node,
	}
	node.SetStreamHandler(downloadResponse, d.onDownloadResponse)
	return d
}

// onDownloadResponse listen for download response protobuf
func (p *UserDownloadProtocol) onDownloadResponse(s p2pNet.Stream) {
	data := &pb.DownloadResponse{}
	buf, err := ioutil.ReadAll(s)
	if err != nil {
		s.Reset()
		lib.Logger.Error(err)
		return
	}
	s.Close()

	err = proto.Unmarshal(buf, data)
	if err != nil {
		lib.Logger.Error(err)
		return
	}
	lib.Logger.WithFields(logrus.Fields{
		"type":      "download response",
		"from":      s.Conn().RemotePeer().String(),
		"hash":      data.Hash,
		"packageId": data.PackageId,
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type":      "download response",
			"from":      s.Conn().RemotePeer().String(),
			"hash":      data.Hash,
			"packageId": data.PackageId,
		}).Warn("failed to authenticate message")
		return
	}

	p.node.downloadInfos.Lock()
	downloadInfo, ok := p.node.downloadInfos.m[data.Hash]
	p.node.downloadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type":      "download response",
			"from":      s.Conn().RemotePeer().String(),
			"hash":      data.Hash,
			"packageId": data.PackageId,
		}).Warn("invalid response")
		return
	}

	if len(data.Data) == 0 {
		done := make(chan bool)
		go func() {
			for {
				if downloadInfo.downloading == 0 {
					done <- true
					return
				}
			}
		}()
		<-done
		// Verify fragments
		targetFile := path.Join(downloadInfo.dst, data.Hash)
		f, err := os.OpenFile(targetFile, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			lib.Logger.Error("failed to create file:", targetFile)
			return
		}
		for i := int64(0); i < data.PackageId; i++ {
			fragment, err := ioutil.ReadFile(path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(i, 10)))
			if err != nil {
				if os.IsNotExist(err) {
					err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, i)
					if err != nil {
						lib.Logger.WithFields(logrus.Fields{
							"type":      "download confirm",
							"to":        s.Conn().RemotePeer().String(),
							"hash":      data.Hash,
							"packageId": i,
						}).Errorf("failed to sent: %v", err)
					} else {
						lib.Logger.WithFields(logrus.Fields{
							"type":      "download confirm",
							"to":        s.Conn().RemotePeer().String(),
							"hash":      data.Hash,
							"packageId": i,
						}).Info("sent success")
					}
				} else {
					downloadInfo.done <- fmt.Errorf("failed to read fragment: %s", path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(i, 10)))
				}
				return
			}
			_, err = f.WriteAt(fragment, lib.PackageSize*i)
		}
		err = f.Truncate(downloadInfo.size)
		if err != nil {
			downloadInfo.done <- fmt.Errorf("failed to truncate file: %s", targetFile)
			f.Close()
			os.Remove(targetFile)
			return
		}
		f.Close()
		// Calculate the pubHash of file
		f, err = os.Open(targetFile)
		defer f.Close()
		if err != nil {
			downloadInfo.done <- fmt.Errorf("failed to open file: %s", targetFile)
			return
		}
		hash, err := crypto.CalFileHash(f)
		if err != nil {
			downloadInfo.done <- fmt.Errorf("failed to calculate file pubHash: %s", targetFile)
			return
		}
		if hash != data.Hash {
			downloadInfo.done <- fmt.Errorf("pubHash is invalid: %s", targetFile)
			return
		}
		err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, data.PackageId)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"type":      "download confirm",
				"to":        s.Conn().RemotePeer().String(),
				"hash":      data.Hash,
				"packageId": data.PackageId,
			}).Errorf("failed to sent: %v", err)
		} else {
			lib.Logger.WithFields(logrus.Fields{
				"type":      "download confirm",
				"to":        s.Conn().RemotePeer().String(),
				"hash":      data.Hash,
				"packageId": data.PackageId,
			}).Info("sent success")
		}
		downloadInfo.done <- nil
	} else {
		downloadInfo.Lock()
		downloadInfo.downloading++
		downloadInfo.Unlock()
		if data.PackageId == 0 {
			err = os.Mkdir(path.Join(lib.DefaultTmpPath, data.Hash), 0700)
			if err != nil && !os.IsExist(err) {
				downloadInfo.done <- errors.New("failed to create storage directory")
			}
		}
		filename := path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(data.PackageId, 10))
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			downloadInfo.done <- fmt.Errorf("failed to open file: %s", filename)
			return
		}
		_, err = f.Write(data.Data)
		if err != nil {
			downloadInfo.done <- fmt.Errorf("failed to write data to file: %s", filename)
			return
		}
		downloadInfo.Lock()
		downloadInfo.downloading--
		downloadInfo.Unlock()
	}
}

// SendDownloadProtocol tag the information of download request then send it.
func (p *UserDownloadProtocol) SendDownloadProtocol(peerID p2pPeer.ID, dst, owner, hash string, size int64) error {
	done := make(chan error)
	p.node.downloadInfos.Lock()
	p.node.downloadInfos.m[hash] = &userDownloadInfo{
		dst:  dst,
		size: size,
		done: done,
	}
	p.node.downloadInfos.Unlock()
	req := &pb.DownloadRequest{
		MessageData: p.node.NewMessageData(uuid.New().String(), true),
		Owner:       owner,
		Hash:        hash,
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerID, downloadRequest, req)
	if !ok {
		ok = p.node.sendProtoMessage(peerID, downloadRequest, req)
		if !ok {
			return errors.New("failed to send download protocol")
		}
	}
	err = <-done
	p.node.downloadInfos.Lock()
	delete(p.node.downloadInfos.m, hash)
	p.node.downloadInfos.Unlock()
	return err
}

// sendDownloadConfirm send the download confirm protobuf
func (p *UserDownloadProtocol) sendDownloadConfirm(peerID p2pPeer.ID, messageID, hash string, id int64) error {
	req := &pb.DownloadConfirm{
		MessageData: p.node.NewMessageData(messageID, true),
		Hash:        hash,
		PackageId:   id,
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerID, downloadConfirm, req)
	if !ok {
		ok = p.node.sendProtoMessage(peerID, downloadConfirm, req)
		if !ok {
			return errors.New("failed to send download confirm protocol")
		}
	}
	return nil
}
