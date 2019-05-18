package p2p

import (
	host "github.com/libp2p/go-libp2p-host"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
	"os"
)

func UploadFile(inFile *os.File, dst string, signature tpUser.Operation) error {
	//seas, err := lib.ListSeasPeerId("", 20)
	//if err != nil {
	//	return err
	//}
	//done := make(chan bool)
	//n := NewUserNode(host, done)
	//for _, s := range seas {
	//	err = n.UserUploadQueryProtocol.Send()
	//}
	return nil
}

func DownloadFile(hash, dst string) error {
	return nil
}

type UserNode struct {
	*Node
	seas      []string
	operation tpUser.Operation
	*UserUploadQueryProtocol
	*UserUploadProtocol
}

func NewUserNode(host host.Host, done chan bool) *UserNode {
	n := &UserNode{Node: NewNode(host), seas: make([]string, 0)}
	n.UserUploadQueryProtocol = NewUserUploadQueryProtocol(n, done)
	n.UserUploadProtocol = NewUserUploadProtocol(n, done)
	return n
}
