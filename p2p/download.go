package p2p

import (
	inet "github.com/libp2p/go-libp2p-net"
)

const (
	downloadRequest  = "/download/request/1.0.0"
	downloadResponse = "/download/response/1.0.0"
)

type SeaDownloadProtocol struct {
	node     *SeaNode
	requests map[string]*DownloadRequest
}

func NewSeaDownloadProtocol(node *SeaNode) *SeaDownloadProtocol {
	d := &SeaDownloadProtocol{
		node:     node,
		requests: make(map[string]*DownloadRequest),
	}
	node.SetStreamHandler(downloadRequest, d.onDownloadRequest)
	return d
}

func (d *SeaDownloadProtocol) onDownloadRequest(s inet.Stream) {

}

type UserDownloadProtocol struct {
	node     *UserNode
	responses map[string]*DownloadResponse
	done     chan bool
}

func NewUserDownloadProtocol(node *UserNode, done chan bool) *UserDownloadProtocol {
	d := &UserDownloadProtocol{
		node:     node,
		responses: make(map[string]*DownloadResponse),
		done:     done,
	}
	node.SetStreamHandler(downloadResponse, d.onDownloadResponse)
	return d
}

func (d *UserDownloadProtocol) onDownloadResponse(s inet.Stream) {}