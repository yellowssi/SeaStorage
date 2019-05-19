package p2p

import (
	inet "github.com/libp2p/go-libp2p-net"
	"gitlab.com/SeaStorage/SeaStorage/p2p/pb"
)

const (
	downloadRequest  = "/download/request/1.0.0"
	downloadResponse = "/download/response/1.0.0"
)

type SeaDownloadProtocol struct {
	node     *SeaNode
	requests map[string]map[string]*pb.DownloadRequest
}

func NewSeaDownloadProtocol(node *SeaNode) *SeaDownloadProtocol {
	d := &SeaDownloadProtocol{
		node:     node,
		requests: make(map[string]map[string]*pb.DownloadRequest),
	}
	node.SetStreamHandler(downloadRequest, d.onDownloadRequest)
	return d
}

func (p *SeaDownloadProtocol) onDownloadRequest(s inet.Stream) {

}

type UserDownloadProtocol struct {
	node      *UserNode
	downloads map[string]chan bool
}

func NewUserDownloadProtocol(node *UserNode) *UserDownloadProtocol {
	d := &UserDownloadProtocol{
		node:      node,
		downloads: make(map[string]chan bool),
	}
	node.SetStreamHandler(downloadResponse, d.onDownloadResponse)
	return d
}

func (p *UserDownloadProtocol) onDownloadResponse(s inet.Stream) {}

func (p *UserDownloadProtocol) SendDownloadProtocol() {

}
