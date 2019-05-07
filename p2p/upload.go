package p2p

import (
	inet "github.com/libp2p/go-libp2p-net"
)

const (
	uploadQueryRequest = "/upload/queryreq/1.0.0"
	uploadQueryResponse = "/upload/queryres/1.0.0"
	uploadRequest = "/upload/request/1.0.0"
	uploadResponse = "/upload/response/1.0.0"
)


type UploadQueryProtocol struct {
	node     *Node
	requests map[string]*UploadRequest
	done     chan bool
}

func NewUploadQueryProtocol(node *Node, done chan bool) *UploadQueryProtocol {
	p := &UploadQueryProtocol{
		node:     node,
		requests: make(map[string]*UploadRequest),
		done:     done,
	}
	node.SetStreamHandler(uploadQueryRequest, p.onUploadQueryRequest)
	node.SetStreamHandler(uploadQueryResponse, p.onUploadQueryResponse)
	return p
}

func (p *UploadQueryProtocol) onUploadQueryRequest(s inet.Stream) {

}

func (p *UploadQueryProtocol) onUploadQueryResponse(s inet.Stream) {

}

type UploadProtocol struct {
	node     *Node
	requests map[string]*UploadRequest
	done     chan bool
}

func NewUploadProtocol(node *Node, done chan bool) *UploadProtocol {
	p := &UploadProtocol{
		node:     node,
		requests: make(map[string]*UploadRequest),
		done:     done,
	}
	node.SetStreamHandler(uploadRequest, p.onUploadRequest)
	node.SetStreamHandler(uploadResponse, p.onUploadResponse)
	return p
}

func (p *UploadProtocol) onUploadRequest(s inet.Stream) {

}

func (p *UploadProtocol) onUploadResponse(s inet.Stream) {

}
