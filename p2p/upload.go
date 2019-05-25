package p2p

import (
	"errors"
	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	inet "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpPayload "gitlab.com/SeaStorage/SeaStorage-TP/payload"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p/pb"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"sync"
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

type seaUploadInfo struct {
	sync.RWMutex
	downloading int
	query       *pb.UploadQueryRequest
	hash        string
}

type SeaUploadQueryProtocol struct {
	node *SeaNode
}

func NewSeaUploadQueryProtocol(node *SeaNode) *SeaUploadQueryProtocol {
	p := &SeaUploadQueryProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadQueryRequest, p.onUploadQueryRequest)
	return p
}

func (p *SeaUploadQueryProtocol) onUploadQueryRequest(s inet.Stream) {
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
			lib.Logger.Error("failed to create directory:", path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey)))
			return
		}
	}

	resp := &pb.UploadQueryResponse{
		MessageData: p.node.NewMessageData(data.MessageData.Id, false),
		Tag:         data.Tag,
	}
	signature, err := p.node.signProtoMessage(resp)
	if err != nil {
		lib.Logger.Error("failed to sign response")
		return
	}
	resp.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(s.Conn().RemotePeer(), uploadQueryResponse, resp)
	if ok {
		uploadInfos, ok := p.node.uploadInfos[s.Conn().RemotePeer()]
		if !ok {
			p.node.uploadInfos[s.Conn().RemotePeer()] = map[string]*seaUploadInfo{data.Tag: {query: data}}
		} else {
			uploadInfos[data.Tag] = &seaUploadInfo{query: data}
		}
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query response",
			"to":   s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Info("upload query response sent success")
	} else {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query response",
			"to":   s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Error("failed to send upload query response")
	}
}

type SeaUploadProtocol struct {
	node *SeaNode
}

func NewSeaUploadProtocol(node *SeaNode) *SeaUploadProtocol {
	p := &SeaUploadProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadRequest, p.onUploadRequest)
	return p
}

func (p *SeaUploadProtocol) onUploadRequest(s inet.Stream) {
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
	}).Info("received upload request")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to authenticate message")
		return
	}

	uploadInfoMap, ok := p.node.uploadInfos[s.Conn().RemotePeer()]
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid upload request")
		return
	}
	uploadInfo, ok := uploadInfoMap[data.Tag]
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid upload request")
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
		storagePath := path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey))
		targetFile := path.Join(storagePath, data.Tag)
		f, err := os.OpenFile(targetFile, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			lib.Logger.Error("failed to create file:", targetFile)
			return
		}
		for i := int64(0); i < data.PackageId; i++ {
			fragment, err := ioutil.ReadFile(path.Join(storagePath, "tmp", data.Tag+"-"+strconv.FormatInt(i, 10)))
			if err != nil {
				if os.IsNotExist(err) {
					err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, "", i)
					if err != nil {
						err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, "", i)
					}
				} else {
					lib.Logger.Error("failed to read fragment:", path.Join(storagePath, "tmp", data.Tag+"-"+strconv.FormatInt(i, 10)))
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
			os.Remove(path.Join(storagePath, "tmp", data.Tag+"-"+strconv.FormatInt(i, 10)))
		}
		err = f.Truncate(uploadInfo.query.Size)
		f.Close()
		if err != nil {
			lib.Logger.Error("failed to truncate file:", targetFile)
			os.Remove(targetFile)
			return
		}
		// Calculate the pubHash of file
		f, err = os.Open(targetFile)
		defer f.Close()
		if err != nil {
			lib.Logger.Error("failed to open file:", targetFile)
			return
		}
		hash, err := crypto.CalFileHash(f)
		if err != nil {
			lib.Logger.Error("failed to calculate file pubHash:", targetFile)
			return
		}
		err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, hash, data.PackageId)
		if err != nil {
			err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, hash, data.PackageId)
		}
		if err == nil {
			uploadInfo.hash = hash
		} else {
			lib.Logger.WithFields(logrus.Fields{
				"type": "upload request",
				"from": s.Conn().RemotePeer().String(),
				"tag":  data.Tag,
			}).Error("failed to sent response")
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

func (p *SeaUploadProtocol) sendUploadResponse(peerId peer.ID, messageId, tag, hash string, id int64) error {
	resp := &pb.UploadResponse{
		MessageData: p.node.NewMessageData(messageId, true),
		Tag:         tag,
		PackageId:   id,
		Hash:        hash,
	}
	signature, err := p.node.signProtoMessage(resp)
	if err != nil {
		return err
	}
	resp.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, uploadResponse, resp)
	if ok {
		lib.Logger.WithFields(logrus.Fields{
			"type":      "upload response",
			"to":        peerId,
			"tag":       resp.Tag,
			"packageId": resp.PackageId,
			"hash":      resp.Hash,
		}).Info("upload response sent success")
		return nil
	} else {
		lib.Logger.WithFields(logrus.Fields{
			"type":      "upload response",
			"to":        peerId,
			"tag":       resp.Tag,
			"packageId": resp.PackageId,
			"hash":      resp.Hash,
		}).Error("failed to sent upload response")
		return errors.New("failed to sent upload response")
	}
}

type SeaOperationProtocol struct {
	node *SeaNode
}

func NewSeaOperationProtocol(node *SeaNode) *SeaOperationProtocol {
	p := &SeaOperationProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadOperation, p.onOperationRequest)
	return p
}

func (p *SeaOperationProtocol) onOperationRequest(s inet.Stream) {
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

	uploadInfo, ok := p.node.uploadInfos[s.Conn().RemotePeer()][data.Tag]
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
	if !op.Verify() || op.Hash != uploadInfo.hash {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to authenticate")
		return
	}

	peerPub := tpCrypto.BytesToHex(data.MessageData.NodePubKey)
	err = os.Rename(path.Join(p.node.storagePath, peerPub, data.Tag), path.Join(p.node.storagePath, peerPub, op.Hash))
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to rename file:", err)
		return
	}

	resp, err := p.node.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action:    tpPayload.SeaStoreFile,
		Name:      p.node.Name,
		Operation: *op,
	}}, lib.DefaultWait)
	if err != nil {
		resp, err = p.node.SendTransaction([]tpPayload.SeaStoragePayload{{
			Action:    tpPayload.SeaStoreFile,
			Name:      p.node.Name,
			Operation: *op,
		}}, lib.DefaultWait)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"type": "operation request",
				"from": s.Conn().RemotePeer().String(),
				"tag":  data.Tag,
			}).Error("failed to send transaction:", err)
			return
		}
	}
	lib.Logger.WithFields(logrus.Fields{
		"type":     "operation request",
		"from":     s.Conn().RemotePeer().String(),
		"tag":      data.Tag,
		"response": resp,
	}).Info("send transaction success")
	delete(p.node.uploadInfos[s.Conn().RemotePeer()], data.Tag)
}

/*
 * User Upload Handler
 */

type userUploadInfo struct {
	sync.RWMutex
	src        *os.File
	packages   int64
	operations map[peer.ID]*tpUser.Operation
	done       chan bool
}

type UserUploadQueryProtocol struct {
	node *UserNode
}

func NewUserUploadQueryProtocol(node *UserNode) *UserUploadQueryProtocol {
	p := &UserUploadQueryProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadQueryResponse, p.onUploadQueryResponse)
	return p
}

func (p *UserUploadQueryProtocol) onUploadQueryResponse(s inet.Stream) {
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

func (p *UserUploadQueryProtocol) SendUploadQuery(peerId peer.ID, tag string, size int64) error {
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

	ok := p.node.sendProtoMessage(peerId, uploadQueryRequest, req)
	if ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query request",
			"to":   peerId,
			"tag":  tag,
			"size": size,
		}).Info("upload query request sent")
		return nil
	}
	return errors.New("upload query failed")
}

type UserUploadProtocol struct {
	node *UserNode
}

func NewUserUploadProtocol(node *UserNode) *UserUploadProtocol {
	p := &UserUploadProtocol{
		node: node,
	}
	node.SetStreamHandler(uploadResponse, p.onUploadResponse)
	return p
}

func (p *UserUploadProtocol) onUploadResponse(s inet.Stream) {
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
				err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, data.PackageId)
				if err != nil {
					lib.Logger.WithFields(logrus.Fields{
						"type":      "upload request",
						"to":        s.Conn().RemotePeer().String(),
						"tag":       data.Tag,
						"packageId": data.PackageId,
					}).Warn("failed to send upload request")
					return
				}
			}
			err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, uploadInfo.packages)
			if err != nil {
				err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, uploadInfo.packages)
				if err != nil {
					lib.Logger.WithFields(logrus.Fields{
						"type":      "upload request",
						"to":        s.Conn().RemotePeer().String(),
						"tag":       data.Tag,
						"packageId": uploadInfo.packages,
					}).Warn("failed to send upload request")
				}
				return
			}
			lib.Logger.WithFields(logrus.Fields{
				"type":      "upload response",
				"from":      s.Conn().RemotePeer().String(),
				"tag":       data.Tag,
				"packageId": data.PackageId,
			}).Info("send upload request success")
			return
		} else if data.PackageId == uploadInfo.packages {
			operation, ok := uploadInfo.operations[s.Conn().RemotePeer()]
			if ok && data.Hash == operation.Hash {
				err = p.node.sendOperationProtocol(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag)
				if err != nil {
					err = p.node.sendOperationProtocol(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag)
					if err != nil {
						lib.Logger.WithFields(logrus.Fields{
							"type": "upload response",
							"from": s.Conn().RemotePeer().String(),
							"tag":  data.Tag,
						}).Warn("failed to send operation request")
					}
				}
				delete(uploadInfo.operations, s.Conn().RemotePeer())
				if len(uploadInfo.operations) == 0 {
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
	}).Warn("invalid upload response")
}

func (p *UserUploadProtocol) sendUpload(peerId peer.ID, messageId, tag string) {
	p.node.uploadInfos.Lock()
	uploadInfo, ok := p.node.uploadInfos.m[tag]
	p.node.uploadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"from": peerId.String(),
			"tag":  tag,
		}).Warn("invalid upload query response")
		return
	}
	for i := int64(0); i <= uploadInfo.packages; i++ {
		err := p.node.sendPackage(peerId, messageId, tag, i)
		if err != nil {
			_ = p.node.sendPackage(peerId, messageId, tag, i)
		}
	}
}

func (p *UserUploadProtocol) sendPackage(peerId peer.ID, messageId, tag string, id int64) error {
	var req *pb.UploadRequest
	p.node.uploadInfos.Lock()
	uploadInfo := p.node.uploadInfos.m[tag]
	p.node.uploadInfos.Unlock()
	if id == uploadInfo.packages {
		req = &pb.UploadRequest{
			MessageData: p.node.NewMessageData(messageId, true),
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
			MessageData: p.node.NewMessageData(messageId, true),
			PackageId:   id,
			Tag:         tag,
			Data:        buf[:n],
		}
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, uploadRequest, req)
	if ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"to":   peerId,
			"tag":  tag,
		}).Info("upload request sent")
		return nil
	}
	return errors.New("failed to send upload request")
}

type UserOperationProtocol struct {
	node *UserNode
}

func NewUserOperationProtocol(n *UserNode) *UserOperationProtocol {
	return &UserOperationProtocol{
		node: n,
	}
}

func (p *UserOperationProtocol) sendOperationProtocol(peerId peer.ID, messageId, tag string) error {
	p.node.uploadInfos.Lock()
	uploadInfoMap := p.node.uploadInfos.m[tag]
	p.node.uploadInfos.Unlock()
	uploadInfoMap.Lock()
	operation := uploadInfoMap.operations[peerId]
	uploadInfoMap.Unlock()
	op := &pb.OperationRequest{
		MessageData: p.node.NewMessageData(messageId, true),
		Tag:         tag,
		Operation:   operation.ToBytes(),
	}
	signature, err := p.node.signProtoMessage(op)
	if err != nil {
		return err
	}
	op.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, uploadOperation, op)
	if ok {
		lib.Logger.WithFields(logrus.Fields{
			"type":      "operation request",
			"to":        peerId,
			"tag":       tag,
			"operation": operation,
		}).Info("operation request sent success")
		return nil
	}
	return errors.New("failed to send operation request")
}
