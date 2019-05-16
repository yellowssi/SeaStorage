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
	requests map[string]*pb.DownloadRequest
}

func NewSeaDownloadProtocol(node *SeaNode) *SeaDownloadProtocol {
	d := &SeaDownloadProtocol{
		node:     node,
		requests: make(map[string]*pb.DownloadRequest),
	}
	node.SetStreamHandler(downloadRequest, d.onDownloadRequest)
	return d
}

func (d *SeaDownloadProtocol) onDownloadRequest(s inet.Stream) {

}

type UserDownloadProtocol struct {
	node      *UserNode
	responses map[string]*pb.DownloadResponse
	done      chan bool
}

func NewUserDownloadProtocol(node *UserNode, done chan bool) *UserDownloadProtocol {
	d := &UserDownloadProtocol{
		node:      node,
		responses: make(map[string]*pb.DownloadResponse),
		done:      done,
	}
	node.SetStreamHandler(downloadResponse, d.onDownloadResponse)
	return d
}

func (d *UserDownloadProtocol) onDownloadResponse(s inet.Stream) {}
