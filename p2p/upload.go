package p2p

import (
	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	inet "github.com/libp2p/go-libp2p-net"
	"github.com/sirupsen/logrus"
	"gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"io/ioutil"
	"os"
	"path"
)

const (
	uploadQueryRequest  = "/upload/queryreq/1.0.0"
	uploadQueryResponse = "/upload/queryres/1.0.0"
	uploadRequest       = "/upload/request/1.0.0"
	uploadResponse      = "/upload/response/1.0.0"
)

type SeaUploadQueryProtocol struct {
	node     *SeaNode
	requests map[string]*UploadRequest
}

func NewSeaUploadQueryProtocol(node *SeaNode) *SeaUploadQueryProtocol {
	p := &SeaUploadQueryProtocol{
		node:     node,
		requests: make(map[string]*UploadRequest),
	}
	node.SetStreamHandler(uploadQueryRequest, p.onUploadQueryRequest)
	return p
}

func (p *SeaUploadQueryProtocol) onUploadQueryRequest(s inet.Stream) {
	data := &UploadQueryRequest{}
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
	}

	tag := crypto.SHA512HexFromHex(data.Path + data.Name)
	if _, err = os.Stat(path.Join(p.node.storagePath)); os.IsNotExist(err) {
		err = os.MkdirAll(path.Join(p.node.storagePath), 0700)
		if err != nil {
			logrus.Error("failed to create directory:", path.Join(p.node.storagePath))
			return
		}
	}
	filePath := path.Join(p.node.storagePath, crypto.BytesToHex(data.MessageData.NodePubKey), tag)
	_, err = os.Create(filePath)
	if err != nil {
		logrus.Error("failed to create file:", filePath)
		return
	}

	resp := &UploadQueryResponse{
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
		logrus.WithFields(logrus.Fields{
			"type": "upload query request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Info("upload query response sent")
	}
}

type SeaUploadProtocol struct {
	node     *SeaNode
	requests map[string]*UploadRequest
}

func NewSeaUploadProtocol(node *SeaNode) *SeaUploadProtocol {
	p := &SeaUploadProtocol{
		node:     node,
		requests: make(map[string]*UploadRequest),
	}
	node.SetStreamHandler(uploadRequest, p.onUploadRequest)
	return p
}

func (p *SeaUploadProtocol) onUploadRequest(s inet.Stream) {

}

type UserUploadQueryProtocol struct {
	node      *UserNode
	responses map[string]*UploadQueryResponse
	done      chan bool
}

func NewUserUploadQueryProtocol(node *UserNode, done chan bool) *UserUploadQueryProtocol {
	p := &UserUploadQueryProtocol{
		node:      node,
		responses: make(map[string]*UploadQueryResponse),
		done:      done,
	}
	node.SetStreamHandler(uploadQueryResponse, p.onUploadQueryResponse)
	return p
}

func (p *UserUploadQueryProtocol) onUploadQueryResponse(s inet.Stream) {
	data := &UploadQueryResponse{}
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

func (p *UserUploadQueryProtocol) Send(path, name string, size int64) error {
	req := &UploadQueryRequest{
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

	//ok := p.node.sendProtoMessage(host.Host(), uploadQueryRequest, req)
	// TODO: multicast
	return nil
}

type UserUploadProtocol struct {
	node      *UserNode
	responses map[string]*UploadResponse
	done      chan bool
}

func NewUserUploadProtocol(node *UserNode, done chan bool) *UserUploadProtocol {
	p := &UserUploadProtocol{
		node:      node,
		responses: make(map[string]*UploadResponse),
		done:      done,
	}
	node.SetStreamHandler(uploadResponse, p.onUploadResponse)
	return p
}

func (p *UserUploadProtocol) onUploadResponse(s inet.Stream) {

}
