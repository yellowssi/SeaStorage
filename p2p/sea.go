package p2p

import (
	host "github.com/libp2p/go-libp2p-host"
)

type SeaNode struct {
	size        int
	storagePath string
	*Node
	*SeaUploadQueryProtocol
	*SeaUploadProtocol
	*SeaDownloadProtocol
}

func NewSeaNode(host host.Host) *SeaNode {
	seaNode := &SeaNode{Node: NewNode(host)}
	seaNode.SeaUploadQueryProtocol = NewSeaUploadQueryProtocol(seaNode)
	seaNode.SeaUploadProtocol = NewSeaUploadProtocol(seaNode)
	seaNode.SeaDownloadProtocol = NewSeaDownloadProtocol(seaNode)
	return seaNode
}
