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
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	p2pNet "github.com/libp2p/go-libp2p-core/network"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/sirupsen/logrus"
	tpCrypto "github.com/yellowssi/SeaStorage-TP/crypto"
	tpUser "github.com/yellowssi/SeaStorage-TP/user"
	"github.com/yellowssi/SeaStorage/crypto"
	"github.com/yellowssi/SeaStorage/lib"
	"github.com/yellowssi/SeaStorage/p2p/pb"
)

const (
	uploadQueryRequest  = "/SeaStorage/upload/queryreq/1.0.0"
	uploadQueryResponse = "/SeaStorage/upload/queryres/1.0.0"
	uploadRequest       = "/SeaStorage/upload/request/1.0.0"
	uploadResponse      = "/SeaStorage/upload/response/1.0.0"
	uploadOperation     = "/SeaStorage/upload/operation/1.0.0"
)

/*
 * Sea Upload Handler
 */

// seaUploadInfo is used for tag of upload
type seaUploadInfo struct {
	sync.RWMutex
	downloading int
	size 		int64
	hash        string
}

// SeaUploadQueryProtocol provides listener for upload query request protobuf and sending upload query response protobuf.
type SeaUploadQueryProtocol struct {
	node *SeaNode
}

// NewSeaUploadQueryProtocol is the construct for SeaUploadQueryProtocol.
func NewSeaUploadQueryProtocol(node *SeaNode) *SeaUploadQueryProtocol {
	p := &SeaUploadQueryProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadQueryRequest, p.onUploadQueryRequest)
	return p
}

// onUploadQueryRequest listen for upload query request protobuf.
func (p *SeaUploadQueryProtocol) onUploadQueryRequest(s p2pNet.Stream) {
	data := &pb.UploadQueryRequest{}
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
		"type": "upload query request",
		"from": s.Conn().RemotePeer().String(),
		"tag":  data.Tag,
		"size": data.Size,
	}).Info("received upload query request")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
			"size": data.Size,
		}).Warn("failed to authenticate message")
		return
	}

	if _, err = os.Stat(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp"), 0700)
		if err != nil {
			lib.Logger.Error("failed to create directory:", path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp"))
			return
		}
	}

	if _, err = os.Stat(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "home")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "home"), 0700)
		if err != nil {
			lib.Logger.Error("failed to create directory:", path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "home"))
			return
		}
	}

	if _, err = os.Stat(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "shared")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "shared"), 0700)
		if err != nil {
			lib.Logger.Error("failed to create directory:", path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "home"))
			return
		}
	}

	err = p.sendUploadQueryResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, data.Size)
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query response",
			"to": s.Conn().RemotePeer().String(),
			"tag": data.Tag,
		}).Errorf("failed to sent: %v", err)
	} else {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query response",
			"to": s.Conn().RemotePeer().String(),
			"tag": data.Tag,
		}).Info("sent success")
	}
}

// sendUploadQueryResponse send upload query response protobuf.
func (p *SeaUploadQueryProtocol) sendUploadQueryResponse(peerID p2pPeer.ID, messageID, tag string, size int64) error {
	resp := &pb.UploadQueryResponse{
		MessageData: p.node.NewMessageData(messageID, false),
		Tag:         tag,
	}
	signature, err := p.node.signProtoMessage(resp)
	if err != nil {
		return fmt.Errorf("failed to sign protobuf: %v", err)
	}
	resp.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerID, uploadQueryResponse, resp)
	if !ok {
		return errors.New("failed to sent proto message")
	}
	p.node.uploadInfos.Lock()
	uploadInfos, ok := p.node.uploadInfos.m[peerID]
	if !ok {
		p.node.uploadInfos.m[peerID] = map[string]*seaUploadInfo{tag: {size: size}}
	} else {
		uploadInfos[tag] = &seaUploadInfo{size: size}
	}
	p.node.uploadInfos.Unlock()
	return nil
}

// SeaUploadProtocol provides listener for upload request protobuf and sending upload response protobuf.
type SeaUploadProtocol struct {
	node *SeaNode
}

// NewSeaUploadProtocol is the construct for SeaUploadProtocol.
func NewSeaUploadProtocol(node *SeaNode) *SeaUploadProtocol {
	p := &SeaUploadProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadRequest, p.onUploadRequest)
	return p
}

// onUploadRequest listen for upload request protobuf.
func (p *SeaUploadProtocol) onUploadRequest(s p2pNet.Stream) {
	data := &pb.UploadRequest{}
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
		"type": "upload request",
		"from": s.Conn().RemotePeer().String(),
		"tag":  data.Tag,
	}).Info("received protobuf")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to authenticate message")
		return
	}

	p.node.uploadInfos.Lock()
	uploadInfoMap, ok := p.node.uploadInfos.m[s.Conn().RemotePeer()]
	p.node.uploadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid protobuf")
		return
	}
	p.node.uploadInfos.Lock()
	uploadInfo, ok := uploadInfoMap[data.Tag]
	p.node.uploadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid protobuf")
		return
	}

	if len(data.Data) == 0 {
		done := make(chan bool)
		go func() {
			for {
				if uploadInfo.downloading == 0 {
					done <- true
					return
				}
			}
		}()
		<-done
		// Verify fragments
		storagePath := path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp")
		targetFile := path.Join(storagePath, data.Tag)
		f, err := os.OpenFile(targetFile, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			lib.Logger.Error("failed to create file:", targetFile)
			return
		}
		for i := int64(0); i < data.PackageId; i++ {
			fragment, err := ioutil.ReadFile(path.Join(storagePath, data.Tag+"-"+strconv.FormatInt(i, 10)))
			if err != nil {
				if os.IsNotExist(err) {
					err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, "", i)
					if err != nil {
						lib.Logger.WithFields(logrus.Fields{
							"type": "upload response",
							"to": s.Conn().RemotePeer().String(),
							"tag": data.Tag,
							"packageId": i,
						}).Errorf("failed to sent: %v", err)
					} else {
						lib.Logger.WithFields(logrus.Fields{
							"type": "upload response",
							"to": s.Conn().RemotePeer().String(),
							"tag": data.Tag,
							"packageId": i,
						}).Info("sent success")
					}
				} else {
					lib.Logger.Error("failed to read fragment:", path.Join(storagePath, data.Tag+"-"+strconv.FormatInt(i, 10)))
				}
				return
			}
			_, err = f.WriteAt(fragment, lib.PackageSize*i)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"peer": s.Conn().RemotePeer().String(),
					"tag":  data.Tag,
				}).Error("failed to merge fragment")
				return
			}
		}
		for i := int64(0); i < data.PackageId; i++ {
			os.Remove(path.Join(storagePath, data.Tag+"-"+strconv.FormatInt(i, 10)))
		}
		err = f.Truncate(uploadInfo.size)
		f.Close()
		if err != nil {
			lib.Logger.Errorf("failed to truncate file: %s", targetFile)
			os.Remove(targetFile)
			return
		}
		// Calculate the pubHash of file
		f, err = os.Open(targetFile)
		defer f.Close()
		if err != nil {
			lib.Logger.Errorf("failed to open file: %s", targetFile)
			return
		}
		hash, err := crypto.CalFileHash(f)
		if err != nil {
			lib.Logger.Errorf("failed to calculate file pubHash: %s", targetFile)
			return
		}
		err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, hash, data.PackageId)
		if err == nil {
			lib.Logger.WithFields(logrus.Fields{
				"type": "upload response",
				"to": s.Conn().RemotePeer().String(),
				"tag": data.Tag,
			}).Info("sent success")
			uploadInfo.hash = hash
		} else {
			lib.Logger.WithFields(logrus.Fields{
				"type": "upload response",
				"to": s.Conn().RemotePeer().String(),
				"tag":  data.Tag,
			}).Error("failed to sent protobuf")
			// TODO: clean failed file
		}
	} else {
		uploadInfo.Lock()
		uploadInfo.downloading++
		uploadInfo.Unlock()
		filename := path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp", data.Tag+"-"+strconv.FormatInt(data.PackageId, 10))
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			lib.Logger.Error("failed to create fragment:", err)
			s.Reset()
		}
		_, err = f.WriteAt(data.Data, 0)
		if err != nil {
			lib.Logger.Error("failed to write data to file:", filename)
		}
		uploadInfo.Lock()
		uploadInfo.downloading--
		uploadInfo.Unlock()
	}
}

// sendUploadResponse send upload response protobuf.
func (p *SeaUploadProtocol) sendUploadResponse(peerID p2pPeer.ID, messageID, tag, hash string, id int64) error {
	resp := &pb.UploadResponse{
		MessageData: p.node.NewMessageData(messageID, true),
		Tag:         tag,
		PackageId:   id,
		Hash:        hash,
	}
	signature, err := p.node.signProtoMessage(resp)
	if err != nil {
		return fmt.Errorf("failed to sign proto message: %v", err)
	}
	resp.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerID, uploadResponse, resp)
	if ok {
		return nil
	}
	return errors.New("failed to sent upload response")
}

// SeaOperationProtocol provides listener for operation request protobuf.
type SeaOperationProtocol struct {
	node *SeaNode
}

// NewSeaOperationProtocol is the construct for SeaOperationProtocol.
func NewSeaOperationProtocol(node *SeaNode) *SeaOperationProtocol {
	p := &SeaOperationProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadOperation, p.onOperationRequest)
	return p
}

// onOperationRequest listen for operation request protobuf.
func (p *SeaOperationProtocol) onOperationRequest(s p2pNet.Stream) {
	data := &pb.OperationRequest{}
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
		"type": "operation request",
		"from": s.Conn().RemotePeer().String(),
		"tag":  data.Tag,
	}).Info("received operation request")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to authenticate message")
		return
	}

	p.node.uploadInfos.Lock()
	uploadInfo, ok := p.node.uploadInfos.m[s.Conn().RemotePeer()][data.Tag]
	p.node.uploadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid operation")
		return
	}

	op, err := tpUser.OperationFromBytes(data.Operation)
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to unmarshal:", err)
		return
	}

	if !op.Verify() || op.PublicKey != tpCrypto.BytesToHex(data.MessageData.NodePubKey) || op.Hash != uploadInfo.hash {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid operation")
		return
	}

	peerPub := tpCrypto.BytesToHex(data.MessageData.NodePubKey)
	err = os.Rename(path.Join(p.node.storagePath, peerPub, "tmp", data.Tag), path.Join(p.node.storagePath, peerPub, "home", op.Hash))
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to rename file:", err)
		return
	}

	p.node.operations.Lock()
	p.node.operations.m[tpCrypto.SHA512HexFromBytes(op.ToBytes())] = *op
	p.node.operations.Unlock()
	p.node.uploadInfos.Lock()
	delete(p.node.uploadInfos.m[s.Conn().RemotePeer()], data.Tag)
	p.node.uploadInfos.Unlock()
}

/*
 * User Upload Handler
 */

// userUploadInfo is used for tag of upload file
type userUploadInfo struct {
	sync.RWMutex
	src        *os.File
	packages   int64
	operations map[p2pPeer.ID]*tpUser.Operation
	done       chan bool
}

// UserUploadQueryProtocol provides sending upload query request protobuf.
type UserUploadQueryProtocol struct {
	node *UserNode
}

// NewUserUploadQueryProtocol is the construct for UserUploadQueryProtocol.
func NewUserUploadQueryProtocol(node *UserNode) *UserUploadQueryProtocol {
	p := &UserUploadQueryProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadQueryResponse, p.onUploadQueryResponse)
	return p
}

// onUploadQueryResponse listen for upload query response protobuf.
func (p *UserUploadQueryProtocol) onUploadQueryResponse(s p2pNet.Stream) {
	data := &pb.UploadQueryResponse{}
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
		"type": "upload query response",
		"from": s.Conn().RemotePeer().String(),
		"tag":  data.Tag,
	}).Info("received upload query response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query response",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to authenticate message")
		return
	}

	p.node.sendUpload(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag)
}

// SendUploadQuery send upload query protobuf.
func (p *UserUploadQueryProtocol) SendUploadQuery(peerID p2pPeer.ID, tag string, size int64) error {
	req := &pb.UploadQueryRequest{
		MessageData: p.node.NewMessageData(uuid.New().String(), true),
		Tag:         tag,
		Size:        size,
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature

	ok := p.node.sendProtoMessage(peerID, uploadQueryRequest, req)
	if !ok {
		return errors.New("send proto message failed")
	}
	return nil
}

// UserUploadProtocol provides sending upload request protobuf and listener for upload response protobuf.
type UserUploadProtocol struct {
	node *UserNode
}

// NewUserUploadProtocol is the construct for UserUploadProtocol.
func NewUserUploadProtocol(node *UserNode) *UserUploadProtocol {
	p := &UserUploadProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadResponse, p.onUploadResponse)
	return p
}

// onUploadResponse listen for upload response protobuf.
func (p *UserUploadProtocol) onUploadResponse(s p2pNet.Stream) {
	data := &pb.UploadResponse{}
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
		"type": "upload response",
		"from": s.Conn().RemotePeer().String(),
		"tag":  data.Tag,
	}).Info("received upload response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload response",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to authenticate message")
		return
	}

	p.node.uploadInfos.Lock()
	uploadInfo, ok := p.node.uploadInfos.m[data.Tag]
	p.node.uploadInfos.Unlock()
	if ok {
		if data.PackageId < uploadInfo.packages {
			err := p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, data.PackageId)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"type":      "upload request",
					"to":        s.Conn().RemotePeer().String(),
					"tag":       data.Tag,
					"packageId": data.PackageId,
				}).Errorf("failed to send protobuf: %v", err)
				return
			}
			lib.Logger.WithFields(logrus.Fields{
				"type":      "upload request",
				"to":        s.Conn().RemotePeer().String(),
				"tag":       data.Tag,
				"packageId": data.PackageId,
			}).Info("sent success")
			err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, uploadInfo.packages)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"type":      "upload request",
					"to":        s.Conn().RemotePeer().String(),
					"tag":       data.Tag,
					"packageId": uploadInfo.packages,
				}).Warn("failed to send upload request")
				return
			}
			lib.Logger.WithFields(logrus.Fields{
				"type":      "upload response",
				"from":      s.Conn().RemotePeer().String(),
				"tag":       data.Tag,
				"packageId": uploadInfo.packages,
			}).Info("sent success")
			return
		} else if data.PackageId == uploadInfo.packages {
			uploadInfo.Lock()
			operation, ok := uploadInfo.operations[s.Conn().RemotePeer()]
			uploadInfo.Unlock()
			if ok && data.Hash == operation.Hash {
				err = p.node.sendOperationProtocol(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag)
				if err != nil {
					lib.Logger.WithFields(logrus.Fields{
						"type": "operation request",
						"to": s.Conn().RemotePeer().String(),
						"tag":  data.Tag,
					}).Errorf("failed to send protobuf: %v", err)
				}
				uploadInfo.Lock()
				delete(uploadInfo.operations, s.Conn().RemotePeer())
				length := len(uploadInfo.operations)
				uploadInfo.Unlock()
				if length == 0 {
					uploadInfo.done <- true
				}
				return
			}
		}
	}
	lib.Logger.WithFields(logrus.Fields{
		"type": "upload response",
		"from": s.Conn().RemotePeer().String(),
		"tag":  data.Tag,
		"hash": data.Hash,
	}).Warn("invalid protobuf")
}

// sendUpload send packages of file.
func (p *UserUploadProtocol) sendUpload(peerID p2pPeer.ID, messageID, tag string) {
	p.node.uploadInfos.Lock()
	uploadInfo, ok := p.node.uploadInfos.m[tag]
	p.node.uploadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"from": peerID.String(),
			"tag":  tag,
		}).Warn("invalid upload query response")
		return
	}
	for i := int64(0); i <= uploadInfo.packages; i++ {
		err := p.node.sendPackage(peerID, messageID, tag, i)
		if err != nil {
			err = p.node.sendPackage(peerID, messageID, tag, i)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"to":      peerID.String(),
					"tag":     tag,
					"package": i,
				}).Warn("failed to sent package")
			}
		}
	}
}

// sendPackage send upload request protobuf.
func (p *UserUploadProtocol) sendPackage(peerID p2pPeer.ID, messageID, tag string, id int64) error {
	var req *pb.UploadRequest
	p.node.uploadInfos.Lock()
	uploadInfo := p.node.uploadInfos.m[tag]
	p.node.uploadInfos.Unlock()
	if id == uploadInfo.packages {
		req = &pb.UploadRequest{
			MessageData: p.node.NewMessageData(messageID, true),
			PackageId:   id,
			Tag:         tag,
			Data:        nil,
		}
	} else {
		buf := make([]byte, lib.PackageSize)
		n, err := uploadInfo.src.ReadAt(buf, id*lib.PackageSize)
		if err != nil && err != io.EOF {
			return err
		}
		req = &pb.UploadRequest{
			MessageData: p.node.NewMessageData(messageID, true),
			PackageId:   id,
			Tag:         tag,
			Data:        buf[:n],
		}
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return fmt.Errorf("failed to sign proto message: %v", err)
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerID, uploadRequest, req)
	if ok {
		return nil
	}
	return errors.New("failed to send proto message")
}

// UserOperationProtocol provides sending operation request protobuf.
type UserOperationProtocol struct {
	node *UserNode
}

// NewUserOperationProtocol is the construct for UserOperationProtocol.
func NewUserOperationProtocol(n *UserNode) *UserOperationProtocol {
	return &UserOperationProtocol{
		node: n,
	}
}

// sendOperationProtocol send operation request and delete upload info of the tag.
func (p *UserOperationProtocol) sendOperationProtocol(peerID p2pPeer.ID, messageID, tag string) error {
	p.node.uploadInfos.Lock()
	uploadInfoMap := p.node.uploadInfos.m[tag]
	p.node.uploadInfos.Unlock()
	uploadInfoMap.Lock()
	operation := uploadInfoMap.operations[peerID]
	uploadInfoMap.Unlock()
	op := &pb.OperationRequest{
		MessageData: p.node.NewMessageData(messageID, true),
		Tag:         tag,
		Operation:   operation.ToBytes(),
	}
	signature, err := p.node.signProtoMessage(op)
	if err != nil {
		return err
	}
	op.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerID, uploadOperation, op)
	if !ok {
		return errors.New("failed to send proto message")
	}
	return nil
}
