package p2p

import (
	"errors"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	inet "github.com/libp2p/go-libp2p-net"
	peer "github.com/libp2p/go-libp2p-peer"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"gitlab.com/SeaStorage/SeaStorage/p2p/pb"
)

const (
	downloadRequest  = "/SeaStorage/download/request/1.0.0"
	downloadResponse = "/SeaStorage/download/response/1.0.0"
	downloadConfirm  = "/SeaStorage/download/confirm/1.0.0"
)

type seaDownloadInfo struct {
	src      *os.File
	packages int64
}

type SeaDownloadProtocol struct {
	node *SeaNode
}

func NewSeaDownloadProtocol(node *SeaNode) *SeaDownloadProtocol {
	p := &SeaDownloadProtocol{
		node: node,
	}
	node.SetStreamHandler(downloadRequest, p.onDownloadRequest)
	return p
}

func (p *SeaDownloadProtocol) onDownloadRequest(s inet.Stream) {
	data := &pb.DownloadRequest{}
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
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload response",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	err = p.sendDownload(s.Conn().RemotePeer(), data.MessageData.Id, tpCrypto.BytesToHex(data.MessageData.NodePubKey), data.Hash)
	if err != nil {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("invalid download request or failed to send response")
	} else {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download request",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Info("sent response success")
	}
}

func (p *SeaDownloadProtocol) sendDownload(peerId peer.ID, messageId, peerPub, hash string) error {
	filename := path.Join(p.node.storagePath, peerPub, hash)
	src, err := os.Open(filename)
	if err != nil {
		return err
	}
	stat, err := src.Stat()
	if err != nil {
		return err
	}
	packages := int64(math.Ceil(float64(stat.Size()) / float64(lib.PackageSize)))
	peerSrcs, ok := p.node.downloadInfos[peerId]
	if ok {
		peerSrcs[hash] = &seaDownloadInfo{
			src:      src,
			packages: packages,
		}
	} else {
		p.node.downloadInfos[peerId] = map[string]*seaDownloadInfo{hash: {
			src:      src,
			packages: packages,
		}}
	}
	for i := int64(0); i <= packages; i++ {
		err := p.sendPackage(peerId, messageId, peerPub, hash, i)
		if err != nil {
			err = p.sendPackage(peerId, messageId, peerPub, hash, i)
		}
	}
	return err
}

func (p *SeaDownloadProtocol) sendPackage(peerId peer.ID, messageId, peerPub, hash string, id int64) error {
	var req *pb.DownloadResponse
	uploadInfo := p.node.downloadInfos[peerId][hash]
	if id == uploadInfo.packages {
		req = &pb.DownloadResponse{
			MessageData: p.node.NewMessageData(messageId, true),
			PackageId:   id,
			Hash:        hash,
			Data:        nil,
		}
	} else {
		buf := make([]byte, lib.PackageSize)
		n, err := uploadInfo.src.ReadAt(buf, id*lib.PackageSize)
		if err != nil && err != io.EOF {
			return err
		}
		req = &pb.DownloadResponse{
			MessageData: p.node.NewMessageData(messageId, true),
			PackageId:   id,
			Hash:        hash,
			Data:        buf[:n],
		}
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, downloadResponse, req)
	if ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download response",
			"to":   peerId,
			"data": req.String(),
		}).Info("sent success")
		return nil
	}
	return errors.New("failed to send download response protocol")
}

type SeaDownloadConfirmProtocol struct {
	node *SeaNode
}

func NewSeaDownloadConfirmProtocol(node *SeaNode) *SeaDownloadConfirmProtocol {
	p := &SeaDownloadConfirmProtocol{node: node}
	node.SetStreamHandler(downloadConfirm, p.onDownloadConfirm)
	return p
}

func (p *SeaDownloadConfirmProtocol) onDownloadConfirm(s inet.Stream) {
	data := &pb.DownloadConfirm{}
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
		"type": "upload confirm",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload confirm",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	downloadInfo, ok := p.node.downloadInfos[s.Conn().RemotePeer()][data.Hash]
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload confirm",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("invalid protocol")
		return
	}

	if data.PackageId == downloadInfo.packages {
		delete(p.node.downloadInfos[s.Conn().RemotePeer()], data.Hash)
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload confirm",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Info("download success")
	} else {
		peerPub := tpCrypto.BytesToHex(data.MessageData.NodePubKey)
		err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, peerPub, data.Hash, data.PackageId)
		if err != nil {
			err = p.node.sendPackage(s.Conn().RemotePeer(), data.MessageData.Id, peerPub, data.Hash, data.PackageId)
			if err != nil {
				lib.Logger.Error("failed to send package")
				return
			}
		}
	}
}

type userDownloadInfo struct {
	sync.RWMutex
	downloading int
	dst         string
	size        int64
	done        chan bool
}

type UserDownloadProtocol struct {
	node *UserNode
}

func NewUserDownloadProtocol(node *UserNode) *UserDownloadProtocol {
	d := &UserDownloadProtocol{
		node: node,
	}
	node.SetStreamHandler(downloadResponse, d.onDownloadResponse)
	return d
}

func (p *UserDownloadProtocol) onDownloadResponse(s inet.Stream) {
	data := &pb.DownloadResponse{}
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
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload response",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	p.node.downloadInfos.Lock()
	downloadInfo, ok := p.node.downloadInfos.m[data.Hash]
	p.node.downloadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "upload response",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("invalid response")
		return
	}

	if len(data.Data) == 0 {
		done := make(chan bool)
		go func() {
			for {
				if downloadInfo.downloading == 0 {
					done <- true
					return
				}
			}
		}()
		<-done
		// Verify fragments
		targetFile := path.Join(downloadInfo.dst, data.Hash)
		f, err := os.OpenFile(targetFile, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			lib.Logger.Error("failed to create file:", targetFile)
			return
		}
		for i := int64(0); i < data.PackageId; i++ {
			fragment, err := ioutil.ReadFile(path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(i, 10)))
			if err != nil {
				if os.IsNotExist(err) {
					err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, i)
					if err != nil {
						err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, i)
					}
				} else {
					lib.Logger.Error("failed to read fragment:", path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(i, 10)))
				}
				return
			}
			_, err = f.WriteAt(fragment, lib.PackageSize*i)
		}
		err = f.Truncate(downloadInfo.size)
		if err != nil {
			lib.Logger.Error("failed to truncate file:", targetFile)
			f.Close()
			os.Remove(targetFile)
			return
		}
		f.Close()
		// Calculate the pubHash of file
		f, err = os.Open(targetFile)
		defer f.Close()
		if err != nil {
			lib.Logger.Error("failed to open file:", targetFile)
			return
		}
		hash, err := crypto.CalFileHash(f)
		if err != nil {
			lib.Logger.Error("failed to calculate file pubHash:", targetFile)
			return
		}
		if hash != data.Hash {
			lib.Logger.Error("pubHash is invalid:", targetFile)
			return
		}
		err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, data.PackageId)
		if err != nil {
			err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, data.PackageId)
			if err != nil {
				lib.Logger.Error("failed to send confirm")
			}
		}
		downloadInfo.done <- true
	} else {
		downloadInfo.Lock()
		downloadInfo.downloading++
		downloadInfo.Unlock()
		if data.PackageId == 0 {
			err = os.Mkdir(path.Join(lib.DefaultTmpPath, data.Hash), 0700)
			if err != nil && !os.IsExist(err) {
				panic(err)
			}
		}
		filename := path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(data.PackageId, 10))
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			f, err := os.Create(filename)
			if err != nil {
				lib.Logger.Error("failed to create file:", filename)
			}
			_, err = f.Write(data.Data)
			if err != nil {
				lib.Logger.Error("failed to write data to file:", filename)
			}
		} else {
			lib.Logger.Error("file exists:", filename)
		}
		downloadInfo.Lock()
		downloadInfo.downloading--
		downloadInfo.Unlock()
	}
}

func (p *UserDownloadProtocol) SendDownloadProtocol(peerId peer.ID, dst, hash string, size int64) error {
	done := make(chan bool)
	p.node.downloadInfos.Lock()
	p.node.downloadInfos.m[hash] = &userDownloadInfo{
		dst:  dst,
		size: size,
		done: done,
	}
	p.node.downloadInfos.Unlock()
	req := &pb.DownloadRequest{
		MessageData: p.node.NewMessageData(uuid.New().String(), true),
		Hash:        hash,
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, downloadRequest, req)
	if !ok {
		ok = p.node.sendProtoMessage(peerId, downloadRequest, req)
		if !ok {
			return errors.New("failed to send download protocol")
		}
	}
	<-done
	p.node.downloadInfos.Lock()
	delete(p.node.downloadInfos.m, hash)
	p.node.downloadInfos.Unlock()
	return nil
}

func (p *UserDownloadProtocol) sendDownloadConfirm(peerId peer.ID, messageId, hash string, id int64) error {
	req := &pb.DownloadConfirm{
		MessageData: p.node.NewMessageData(messageId, true),
		Hash:        hash,
		PackageId:   id,
	}
	signature, err := p.node.signProtoMessage(req)
	if err != nil {
		return err
	}
	req.MessageData.Sign = signature
	ok := p.node.sendProtoMessage(peerId, downloadConfirm, req)
	if !ok {
		ok = p.node.sendProtoMessage(peerId, downloadConfirm, req)
		if !ok {
			return errors.New("failed to send download confirm protocol")
		}
	}
	return nil
}
