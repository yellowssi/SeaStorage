package p2p

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	p2pNet "github.com/libp2p/go-libp2p-core/network"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
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

func (p *SeaDownloadProtocol) onDownloadRequest(s p2pNet.Stream) {
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
		"type": "download response",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download response",
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

func (p *SeaDownloadProtocol) sendDownload(peerId p2pPeer.ID, messageId, peerPub, hash string) error {
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
	p.node.downloadInfos.Lock()
	peerSrcs, ok := p.node.downloadInfos.m[peerId]
	if ok {
		peerSrcs[hash] = &seaDownloadInfo{
			src:      src,
			packages: packages,
		}
	} else {
		p.node.downloadInfos.m[peerId] = map[string]*seaDownloadInfo{hash: {
			src:      src,
			packages: packages,
		}}
	}
	p.node.downloadInfos.Unlock()
	for i := int64(0); i <= packages; i++ {
		err := p.sendPackage(peerId, messageId, peerPub, hash, i)
		if err != nil {
			err = p.sendPackage(peerId, messageId, peerPub, hash, i)
		}
	}
	return err
}

func (p *SeaDownloadProtocol) sendPackage(peerId p2pPeer.ID, messageId, peerPub, hash string, id int64) error {
	var req *pb.DownloadResponse
	p.node.downloadInfos.Lock()
	downloadInfo := p.node.downloadInfos.m[peerId][hash]
	p.node.downloadInfos.Unlock()
	if id == downloadInfo.packages {
		req = &pb.DownloadResponse{
			MessageData: p.node.NewMessageData(messageId, true),
			PackageId:   id,
			Hash:        hash,
			Data:        nil,
		}
	} else {
		buf := make([]byte, lib.PackageSize)
		n, err := downloadInfo.src.ReadAt(buf, id*lib.PackageSize)
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

func (p *SeaDownloadConfirmProtocol) onDownloadConfirm(s p2pNet.Stream) {
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
		"type": "download confirm",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download confirm",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("failed to authenticate message")
		return
	}

	p.node.downloadInfos.Lock()
	downloadInfo, ok := p.node.downloadInfos.m[s.Conn().RemotePeer()][data.Hash]
	p.node.downloadInfos.Unlock()
	if !ok {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download confirm",
			"from": s.Conn().RemotePeer(),
			"data": data.String(),
		}).Warn("invalid protocol")
		return
	}

	if data.PackageId == downloadInfo.packages {
		p.node.downloadInfos.Lock()
		delete(p.node.downloadInfos.m[s.Conn().RemotePeer()], data.Hash)
		p.node.downloadInfos.Unlock()
		lib.Logger.WithFields(logrus.Fields{
			"type": "download confirm",
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
	done        chan error
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

func (p *UserDownloadProtocol) onDownloadResponse(s p2pNet.Stream) {
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
		"type": "download response",
		"from": s.Conn().RemotePeer(),
		"data": data.String(),
	}).Info("received response")

	valid := p.node.authenticateMessage(data, data.MessageData)
	if !valid {
		lib.Logger.WithFields(logrus.Fields{
			"type": "download response",
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
			"type": "download response",
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
					downloadInfo.done <- errors.New(fmt.Sprintf("failed to read fragment: %s", path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(i, 10))))
				}
				return
			}
			_, err = f.WriteAt(fragment, lib.PackageSize*i)
		}
		err = f.Truncate(downloadInfo.size)
		if err != nil {
			downloadInfo.done <- errors.New(fmt.Sprintf("failed to truncate file: %s", targetFile))
			f.Close()
			os.Remove(targetFile)
			return
		}
		f.Close()
		// Calculate the pubHash of file
		f, err = os.Open(targetFile)
		defer f.Close()
		if err != nil {
			downloadInfo.done <- errors.New(fmt.Sprintf("failed to open file: %s", targetFile))
			return
		}
		hash, err := crypto.CalFileHash(f)
		if err != nil {
			downloadInfo.done <- errors.New(fmt.Sprintf("failed to calculate file pubHash: %s", targetFile))
			return
		}
		if hash != data.Hash {
			downloadInfo.done <- errors.New(fmt.Sprintf("pubHash is invalid: %s", targetFile))
			return
		}
		err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, data.PackageId)
		if err != nil {
			err = p.sendDownloadConfirm(s.Conn().RemotePeer(), data.MessageData.Id, data.Hash, data.PackageId)
			if err != nil {
				lib.Logger.Warn("failed to send confirm")
			}
		}
		downloadInfo.done <- nil
	} else {
		downloadInfo.Lock()
		downloadInfo.downloading++
		downloadInfo.Unlock()
		if data.PackageId == 0 {
			err = os.Mkdir(path.Join(lib.DefaultTmpPath, data.Hash), 0700)
			if err != nil && !os.IsExist(err) {
				downloadInfo.done <- errors.New("failed to create storage directory")
			}
		}
		filename := path.Join(lib.DefaultTmpPath, data.Hash, data.Hash+"-"+strconv.FormatInt(data.PackageId, 10))
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			downloadInfo.done <- errors.New(fmt.Sprintf("failed to open file: %s", filename))
			return
		}
		_, err = f.Write(data.Data)
		if err != nil {
			downloadInfo.done <- errors.New(fmt.Sprintf("failed to write data to file: %s", filename))
			return
		}
		downloadInfo.Lock()
		downloadInfo.downloading--
		downloadInfo.Unlock()
	}
}

func (p *UserDownloadProtocol) SendDownloadProtocol(peerId p2pPeer.ID, dst, hash string, size int64) error {
	done := make(chan error)
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
	err = <-done
	p.node.downloadInfos.Lock()
	delete(p.node.downloadInfos.m, hash)
	p.node.downloadInfos.Unlock()
	return err
}

func (p *UserDownloadProtocol) sendDownloadConfirm(peerId p2pPeer.ID, messageId, hash string, id int64) error {
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
