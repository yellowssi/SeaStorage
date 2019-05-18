package p2p

import (
	"errors"
	"gitlab.com/SeaStorage/SeaStorage-TP/payload"
	"gitlab.com/SeaStorage/SeaStorage-TP/user"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
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
	"gitlab.com/SeaStorage/SeaStorage/p2p/pb"
)

const (
	uploadQueryRequest  = "/SeaStorage/upload/queryreq/1.0.0"
	uploadQueryResponse = "/SeaStorage/upload/queryres/1.0.0"
	uploadRequest       = "/SeaStorage/upload/request/1.0.0"
	uploadResponse      = "/SeaStorage/upload/response/1.0.0"
	uploadOperation     = "/SeaStorage/upload/operation/1.0.0"
)

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
		logrus.Error(err)
		return
	}
	s.Close()

	err = proto.Unmarshal(buf, data)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.WithFields(logrus.Fields{
		"type": "upload query request",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received request")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		logrus.WithFields(logrus.Fields{
			"type": "upload query request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	tag := tpCrypto.SHA512HexFromHex(data.Path + data.Name)
	if _, err = os.Stat(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp")); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp"), 0700)
		if err != nil {
			logrus.Error("failed to create directory:", path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey)))
			return
		}
	}

	resp := &pb.UploadQueryResponse{
		MessageData: p.node.NewMessageData(data.MessageData.Id, false),
		Tag:         tag,
	}
	signature, err := p.node.signProtoMessage(resp)
	if err != nil {
		logrus.Error("failed to sign response")
		return
	}
	resp.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(s.Conn().RemotePeer(), uploadQueryResponse, resp)
	if ok {
		queryMap, ok := p.node.queries[data.MessageData.NodeId]
		if ok {
			p.node.queries[data.MessageData.NodeId] = map[string]*pb.UploadQueryResponse{tag: resp}
		} else {
			queryMap[tag] = resp
		}
		logrus.WithFields(logrus.Fields{
			"type": "upload query response",
			"to":   s.Conn().RemotePeer(),
			"data": resp.String(),
		}).Info("sent success")
	} else {
		logrus.WithFields(logrus.Fields{
			"type": "upload query response",
			"to":   s.Conn().RemotePeer(),
			"data": resp.String(),
		}).Error("failed to send protocol")
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
		logrus.Error(err)
		return
	}
	s.Close()

	err = proto.Unmarshal(buf, data)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.WithFields(logrus.Fields{
		"type": "upload request",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received request")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		logrus.WithFields(logrus.Fields{
			"type": "upload request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	queryMap, ok := p.queries[data.MessageData.NodeId]
	if !ok {
		logrus.WithFields(logrus.Fields{
			"type": "upload request",
			"from": data.MessageData.NodeId,
		}).Warn("invalid protocol")
		return
	}
	queryResponse, ok := queryMap[data.Tag]
	if !ok {
		logrus.WithFields(logrus.Fields{
			"type": "upload request",
			"from": data.MessageData.NodeId,
		}).Warn("invalid protocol")
		return
	}

	if len(data.Data) == 0 {
		// Verify fragments
		storagePath := path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey))
		targetFile := path.Join(storagePath, data.Tag)
		f, err := os.OpenFile(targetFile, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			logrus.Error("failed to create file:", targetFile)
			return
		}
		for i := int64(0); i < data.Id; i++ {
			fragment, err := ioutil.ReadFile(path.Join(storagePath, "tmp", data.Tag+"-"+strconv.FormatInt(i, 10)))
			if err != nil {
				if os.IsNotExist(err) {
					// TODO: send response for getting missing package
				} else {
					logrus.Error("failed to read fragment:", path.Join(storagePath, "tmp", data.Tag+"-"+strconv.FormatInt(i, 10)))
				}
				return
			}
			_, err = f.WriteAt(fragment, lib.PackageSize*i)
		}
		err = f.Truncate(queryResponse.Size)
		if err != nil {
			logrus.Error("failed to truncate file:", targetFile)
			f.Close()
			os.Remove(targetFile)
			return
		}
		f.Close()
		// Calculate the hash of file
		f, err = os.Open(targetFile)
		defer f.Close()
		if err != nil {
			logrus.Error("failed to open file:", targetFile)
			return
		}
		hash, err := crypto.CalFileHash(f)
		if err != nil {
			logrus.Error("failed to calculate file hash:", targetFile)
			return
		}
		// Send Upload Response
		resp := &pb.UploadResponse{
			Tag:  data.Tag,
			Id:   data.Id,
			Hash: hash,
		}
		signature, err := p.node.signProtoMessage(resp)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"type": "upload response",
				"to":   data.MessageData.NodeId,
				"data": resp.String(),
			}).Error("failed to sign")
			return
		}
		resp.MessageData.Sign = signature
		ok := p.node.sendProtoMessage(s.Conn().RemotePeer(), uploadResponse, resp)
		if ok {
			uploadMap, ok := p.node.uploads[data.MessageData.NodeId]
			if ok {
				p.node.uploads[data.MessageData.NodeId] = map[string]*pb.UploadResponse{data.Tag: resp}
			} else {
				uploadMap[data.Tag] = resp
			}
			logrus.WithFields(logrus.Fields{
				"type": "upload response",
				"to":   s.Conn().RemotePeer(),
				"data": resp.String(),
			}).Info("sent success")
		} else {
			logrus.WithFields(logrus.Fields{
				"type": "upload response",
				"to":   s.Conn().RemotePeer(),
				"data": resp.String(),
			}).Error("failed to sent")
		}
	} else {
		filename := path.Join(p.node.storagePath, tpCrypto.BytesToHex(data.MessageData.NodePubKey), "tmp", data.Tag+"-"+strconv.FormatInt(data.Id, 10))
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			f, err := os.Create(filename)
			if err != nil {
				logrus.Error("failed to create file:", filename)
			}
			_, err = f.Write(data.Data)
			if err != nil {
				logrus.Error("failed to write data to file:", filename)
			}
		} else {
			logrus.Error("file exists:", filename)
		}
	}
}

type SeaOperationProtocol struct {
	node    *SeaNode
	uploads map[string]map[string]*pb.UploadResponse
}

func NewSeaOperationProtocol(node *SeaNode) *SeaOperationProtocol {
	p := &SeaOperationProtocol{
		node:    node,
		uploads: make(map[string]map[string]*pb.UploadResponse),
	}
	node.SetStreamHandler(uploadOperation, p.onOperationRequest)
	return p
}

func (p *SeaOperationProtocol) onOperationRequest(s inet.Stream) {
	data := &pb.OperationRequest{}
	buf, err := ioutil.ReadAll(s)
	if err != nil {
		s.Reset()
		logrus.Error(err)
		return
	}
	s.Close()

	err = proto.Unmarshal(buf, data)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.WithFields(logrus.Fields{
		"type": "operation request",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received request")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		logrus.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	op, err := user.OperationFromBytes(data.Operation)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to unmarshal")
		return
	}
	if !op.Verify() {
		logrus.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate")
		return
	}

	resp, err := p.node.SendTransaction([]payload.SeaStoragePayload{{
		Action:    payload.UserCreateDirectory,
		Name:      p.node.Name,
		Signature: *op,
	}}, lib.DefaultWait)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"type": "operation request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Error("failed to send transaction")
		resp, err = p.node.SendTransaction([]payload.SeaStoragePayload{{
			Action:    payload.UserCreateDirectory,
			Name:      p.node.Name,
			Signature: *op,
		}}, lib.DefaultWait)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"type": "operation request",
				"from": s.Conn().RemotePeer(),
				"data": data.String(),
			}).Error("failed to send transaction")
		}
	} else {
		logrus.WithFields(logrus.Fields{
			"type":     "operation request",
			"from":     s.Conn().RemotePeer(),
			"data":     data.String(),
			"response": resp,
		}).Info("send transaction success")
	}
}

type UserUploadQueryProtocol struct {
	node    *UserNode
	queries map[string]*pb.UploadQueryResponse
	done    chan bool
}

func NewUserUploadQueryProtocol(node *UserNode, done chan bool) *UserUploadQueryProtocol {
	p := &UserUploadQueryProtocol{
		node:    node,
		queries: make(map[string]*pb.UploadQueryResponse),
		done:    done,
	}
	node.SetStreamHandler(uploadQueryResponse, p.onUploadQueryResponse)
	return p
}

func (p *UserUploadQueryProtocol) onUploadQueryResponse(s inet.Stream) {
	data := &pb.UploadQueryResponse{}
	buf, err := ioutil.ReadAll(s)
	if err != nil {
		s.Reset()
		logrus.Error(err)
		return
	}
	s.Close()

	err = proto.Unmarshal(buf, data)
	if err != nil {
		logrus.Error(err)
		return
	}
	logrus.WithFields(logrus.Fields{
		"type": "upload query response",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		logrus.WithFields(logrus.Fields{
			"type": "upload query response",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
	}
	// TODO: Send Upload Request
}

func (p *UserUploadQueryProtocol) Send(peerId peer.ID, path, name string, size int64) error {
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
		logrus.WithFields(logrus.Fields{
			"type": "upload query request",
			"to":   peerId,
			"data": req.String(),
		}).Info("upload query request sent")
		return nil
	}
	return errors.New("upload query failed")
}

type UserUploadProtocol struct {
	node    *UserNode
	uploads map[string]*pb.UploadResponse
	done    chan bool
}

func NewUserUploadProtocol(node *UserNode, done chan bool) *UserUploadProtocol {
	p := &UserUploadProtocol{
		node:    node,
		uploads: make(map[string]*pb.UploadResponse),
		done:    done,
	}
	node.SetStreamHandler(uploadResponse, p.onUploadResponse)
	return p
}

func (p *UserUploadProtocol) onUploadResponse(s inet.Stream) {

}

func (p *UserUploadProtocol) Send(peerId peer.ID, tag string, data []byte) error {
	req := &pb.UploadRequest{
		Tag:  tag,
		Data: data,
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, uploadRequest, req)
	if ok {
		logrus.WithFields(logrus.Fields{
			"type": "upload request",
			"to":   peerId,
			"data": req.String(),
		}).Info("upload request sent")
		return nil
	}
	return errors.New("failed to send upload protocol")
}
