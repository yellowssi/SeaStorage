package p2p

import (
	host "github.com/libp2p/go-libp2p-host"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"os"
)

func UploadFile(inFile *os.File, dst string, signature tpUser.Operation) error {
	return nil
}

func DownloadFile(hash, dst string) error {
	return nil
}

type UserNode struct {
	*Node
	seas map[string]*tpUser.Operation
	*UserUploadQueryProtocol
	*UserUploadProtocol
}

func NewUserNode(host host.Host, done chan bool)  {
	n := &UserNode{Node:NewNode(host), seas: make(map[string]*tpUser.Operation)}
	n.UserUploadQueryProtocol = NewUserUploadQueryProtocol(n, done)
	n.UserUploadProtocol = NewUserUploadProtocol(n, done)
}
