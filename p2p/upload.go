package p2p

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"

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
		"data": data.String(),
	}).Info("received upload query request")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query request",
			"from": s.Conn().RemotePeer().String(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	tag := tpCrypto.SHA512HexFromBytes([]byte(data.Path + data.Name))
	if _, err = os.Stat(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp"), 0700)
		if err != nil {
			lib.Logger.Error("failed to create directory:", path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey)))
			return
		}
	}

	resp := &pb.UploadQueryResponse{
		MessageData: p.node.NewMessageData(data.MessageData.Id, false),
		Tag:         tag,
		Size:        data.Size,
	}
	signature, err := p.node.signProtoMessage(resp)
	if err != nil {
		lib.Logger.Error("failed to sign response")
		return
	}
	resp.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(s.Conn().RemotePeer(), uploadQueryResponse, resp)
	if ok {
		queryMap, ok := p.node.queries[tpCrypto.BytesToHex(data.MessageData.NodePubKey)]
		if !ok {
			p.node.queries[tpCrypto.BytesToHex(data.MessageData.NodePubKey)] = map[string]*pb.UploadQueryResponse{tag: resp}
		} else {
			queryMap[tag] = resp
		}
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query response",
			"to":   s.Conn().RemotePeer().String(),
			"data": resp.String(),
		}).Info("upload query response sent success")
	} else {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload query response",
			"to":   s.Conn().RemotePeer().String(),
			"data": resp.String(),
		}).Error("failed to send upload query response")
	}
}

type SeaUploadProtocol struct {
	node    *SeaNode
	queries map[string]map[string]*pb.UploadQueryResponse
}

func NewSeaUploadProtocol(node *SeaNode) *SeaUploadProtocol {
	p := &SeaUploadProtocol{
		node:    node,
		queries: make(map[string]map[string]*pb.UploadQueryResponse),
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

	queryMap, ok := p.queries[tpCrypto.BytesToHex(data.MessageData.NodePubKey)]
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid protocol")
		return
	}
	queryResponse, ok := queryMap[data.Tag]
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("invalid protocol")
		return
	}

	if len(data.Data) == 0 {
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
		err = f.Truncate(queryResponse.Size)
		f.Close()
		if err != nil {
			lib.Logger.Error("failed to truncate file:", targetFile)
			os.Remove(targetFile)
			return
		}
		// Calculate the hash of file
		f, err = os.Open(targetFile)
		defer f.Close()
		if err != nil {
			lib.Logger.Error("failed to open file:", targetFile)
			return
		}
		hash, err := crypto.CalFileHash(f)
		if err != nil {
			lib.Logger.Error("failed to calculate file hash:", targetFile)
			return
		}
		err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, hash, data.PackageId)
		if err != nil {
			err = p.sendUploadResponse(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, hash, data.PackageId)
		}
		if err == nil {
			uploadMap, ok := p.node.uploads[tpCrypto.BytesToHex(data.MessageData.NodePubKey)]
			if !ok {
				p.node.uploads[tpCrypto.BytesToHex(data.MessageData.NodePubKey)] = map[string]string{data.Tag: hash}
			} else {
				uploadMap[data.Tag] = hash
			}
		} else {
			lib.Logger.WithFields(logrus.Fields{
				"type": "upload request",
				"from": s.Conn().RemotePeer().String(),
				"tag":  data.Tag,
			}).Error("failed to sent response")
		}
	} else {
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
			"type": "upload response",
			"to":   peerId,
			"data": resp.String(),
		}).Info("upload response sent success")
		return nil
	} else {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload response",
			"to":   peerId,
			"data": resp.String(),
		}).Error("failed to sent upload response")
		return errors.New("failed to sent upload response")
	}
}

type SeaOperationProtocol struct {
	node    *SeaNode
	uploads map[string]map[string]string
}

func NewSeaOperationProtocol(node *SeaNode) *SeaOperationProtocol {
	p := &SeaOperationProtocol{
		node:    node,
		uploads: make(map[string]map[string]string),
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

	hash, ok := p.uploads[tpCrypto.BytesToHex(data.MessageData.NodePubKey)][data.Tag]
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
	if !op.Verify() || op.Hash != hash {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Warn("failed to authenticate")
		return
	}

	resp, err := p.node.SendTransaction([]tpPayload.SeaStoragePayload{{
		Action:    tpPayload.UserCreateDirectory,
		Name:      p.node.Name,
		Signature: *op,
	}}, lib.DefaultWait)
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Error("failed to send transaction:", err)
		resp, err = p.node.SendTransaction([]tpPayload.SeaStoragePayload{{
			Action:    tpPayload.UserCreateDirectory,
			Name:      p.node.Name,
			Signature: *op,
		}}, lib.DefaultWait)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"type": "operation request",
				"from": s.Conn().RemotePeer().String(),
				"tag":  data.Tag,
			}).Error("failed to send transaction:", err)
		}
		//return
	}
	lib.Logger.WithFields(logrus.Fields{
		"type":     "operation request",
		"from":     s.Conn().RemotePeer().String(),
		"tag":      data.Tag,
		"response": resp,
	}).Info("send transaction success")
	peerPub := tpCrypto.BytesToHex(data.MessageData.NodePubKey)
	err = os.Rename(path.Join(p.node.storagePath, peerPub, data.Tag), path.Join(p.node.storagePath, peerPub, op.Hash))
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type":     "operation request",
			"from":     s.Conn().RemotePeer().String(),
			"tag":      data.Tag,
			"response": resp,
		}).Warn("failed to rename file:", err)
	}
}

/*
 * User Upload Handler
 */

type UserUploadQueryProtocol struct {
	node *UserNode
	srcs map[string]*os.File
}

func NewUserUploadQueryProtocol(node *UserNode) *UserUploadQueryProtocol {
	p := &UserUploadQueryProtocol{
		node: node,
		srcs: make(map[string]*os.File),
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

func (p *UserUploadQueryProtocol) SendUploadQuery(peerId peer.ID, path, name string, size int64) error {
	req := &pb.UploadQueryRequest{
		MessageData: p.node.NewMessageData(uuid.New().String(), true),
		Path:        path,
		Name:        name,
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
			"data": req.String(),
		}).Info("upload query request sent")
		return nil
	}
	return errors.New("upload query failed")
}

type UserUploadProtocol struct {
	node     *UserNode
	packages map[string]int64
}

func NewUserUploadProtocol(node *UserNode) *UserUploadProtocol {
	p := &UserUploadProtocol{
		node:     node,
		packages: make(map[string]int64),
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

	packages := p.node.packages[data.Tag]
	if data.PackageId < packages {
		err := p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, data.PackageId)
		if err != nil {
			err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, data.PackageId)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"type": "upload response",
					"from": s.Conn().RemotePeer().String(),
					"tag":  data.Tag,
				}).Warn("failed to send upload protocol")
				return
			}
		}
		err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, packages)
		if err != nil {
			err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag, packages)
			if err != nil {
				lib.Logger.WithFields(logrus.Fields{
					"type": "upload response",
					"from": s.Conn().RemotePeer().String(),
					"tag":  data.Tag,
				}).Warn("failed to send upload protocol")
			}
			return
		}
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload response",
			"from": s.Conn().RemotePeer().String(),
			"tag":  data.Tag,
		}).Info("send upload protocol success")
		return
	} else if data.PackageId == packages {
		operation, ok := p.node.operations[data.Tag]
		logrus.WithFields(logrus.Fields{"tag": data.Tag, "operation": operation}).Debug("check")
		if ok && data.Hash == operation.Hash {
			err = p.node.sendOperationProtocol(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag)
			if err != nil {
				err = p.node.sendOperationProtocol(s.Conn().RemotePeer(), data.MessageData.Id, data.Tag)
				if err != nil {
					lib.Logger.WithFields(logrus.Fields{
						"type": "upload response",
						"from": s.Conn().RemotePeer().String(),
						"tag":  data.Tag,
					}).Warn("failed to send operation protocol")
				}
			}
			lib.Logger.WithFields(logrus.Fields{
				"type": "upload response",
				"from": s.Conn().RemotePeer().String(),
				"tag":  data.Tag,
			}).Info("fragment storage success")
			p.node.seas[data.Tag].Remove(s.Conn().RemotePeer())
			if len(p.node.seas[data.Tag].ToSlice()) == 0 {
				lib.Logger.WithFields(logrus.Fields{
					"type": "upload response",
					"from": s.Conn().RemotePeer().String(),
					"data": data.String(),
				}).Info("fragment storage finish")
				p.node.dones[data.Tag] <- true
			}
			return
		}
	}
	lib.Logger.WithFields(logrus.Fields{
		"type": "upload response",
		"from": s.Conn().RemotePeer().String(),
		"data": data.String(),
	}).Warn("invalid response")
}

func (p *UserUploadProtocol) sendUpload(peerId peer.ID, messageId, tag string) {
	packages, ok := p.packages[tag]
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"tag": tag,
		}).Warn("invalid tag")
		return
	}
	for i := int64(0); i <= packages; i++ {
		err := p.node.sendPackage(peerId, messageId, tag, i)
		if err != nil {
			_ = p.node.sendPackage(peerId, messageId, tag, i)
		}
	}
}

func (p *UserUploadProtocol) sendPackage(peerId peer.ID, messageId, tag string, id int64) error {
	var req *pb.UploadRequest
	if id == p.packages[tag] {
		req = &pb.UploadRequest{
			MessageData: p.node.NewMessageData(messageId, true),
			PackageId:   id,
			Tag:         tag,
			Data:        nil,
		}
	} else {
		buf := make([]byte, lib.PackageSize)
		src := p.node.srcs[tag]
		n, err := src.ReadAt(buf, id*lib.PackageSize)
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
			"data": req.String(),
		}).Info("upload request sent")
		return nil
	}
	return errors.New("failed to send upload protocol")
}

type UserOperationProtocol struct {
	node       *UserNode
	operations map[string]*tpUser.Operation
	dones      map[string]chan bool
}

func NewUserOperationProtocol(n *UserNode) *UserOperationProtocol {
	return &UserOperationProtocol{
		node:       n,
		operations: make(map[string]*tpUser.Operation),
		dones:      make(map[string]chan bool),
	}
}

func (p *UserOperationProtocol) sendOperationProtocol(peerId peer.ID, messageId, tag string) error {
	op := &pb.OperationRequest{
		MessageData: p.node.NewMessageData(messageId, true),
		Tag:         tag,
		Operation:   p.operations[tag].ToBytes(),
	}
	signature, err := p.node.signProtoMessage(op)
	if err != nil {
		return err
	}
	op.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, uploadOperation, op)
	if ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "operation request",
			"to":   peerId,
			"data": op.String(),
		}).Info("protocol sent")
		return nil
	}
	return errors.New("failed to send protocol")
}
