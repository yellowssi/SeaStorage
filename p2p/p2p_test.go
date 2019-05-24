package p2p

import (
	"context"
	"github.com/libp2p/go-libp2p"
	p2pCrypto "github.com/libp2p/go-libp2p-crypto"
	p2pDHT "github.com/libp2p/go-libp2p-kad-dht"
	p2pPeer "github.com/libp2p/go-libp2p-peer"
	peerstore "github.com/libp2p/go-libp2p-peerstore"
	"github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

var userCli, seaCli *lib.ClientFramework
var seaNode *SeaNode
var userNode *UserNode
var seaPeer p2pPeer.ID
var seaPub p2pCrypto.PubKey
var userPeer p2pPeer.ID
var pubHash, priHash string
var pubSize, priSize int64

func init() {
	lib.Logger = logrus.New()
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
	lib.GenerateKey("sea", "test")
	lib.GenerateKey("user", "test")
	seaCli, _ = lib.NewClientFramework("test", lib.ClientCategorySea, "./test/sea.priv")
	seaAddr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6667")
	seaPrivBytes, _ := ioutil.ReadFile("./test/sea.priv")
	seaPriv, _ := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(seaPrivBytes)))
	seaPubBytes, _ := ioutil.ReadFile("./test/sea.pub")
	seaPub, _ = p2pCrypto.UnmarshalSecp256k1PublicKey(tpCrypto.HexToBytes(string(seaPubBytes)))
	seaCtx := context.Background()
	seaHost, _ := libp2p.New(seaCtx, libp2p.ListenAddrs(seaAddr), libp2p.Identity(seaPriv))
	seaPeer = seaHost.ID()
	seaNode, _ = NewSeaNode(seaCli, "./test", lib.DefaultStorageSize, seaHost)
	userCli, _ = lib.NewClientFramework("test", lib.ClientCategoryUser, "./test/user.priv")
	userAddr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6666")
	userPrivBytes, _ := ioutil.ReadFile("./test/user.priv")
	userPriv, _ := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(userPrivBytes)))
	userCtx := context.Background()
	userHost, _ := libp2p.New(userCtx, libp2p.ListenAddrs(userAddr), libp2p.Identity(userPriv))
	kadDHT, _ := p2pDHT.New(userCtx, userHost)
	_ = kadDHT.Bootstrap(userCtx)
	sma, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6667/p2p/" + seaPeer.String())
	seaInfo, _ := peerstore.InfoFromP2pAddr(sma)
	_ = userHost.Connect(userCtx, *seaInfo)
	userPeer = userHost.ID()
	userNode = NewUserNode(userHost, userCli)
}

func TestUpload(t *testing.T) {
	go func() {
		src, _ := os.Open("./test/user.pub")
		stat, _ := src.Stat()
		pubSize = stat.Size()
		pubHash, _ = crypto.CalFileHash(src)
		userNode.Upload(src, "/", "test", pubHash, pubSize, []p2pCrypto.PubKey{seaPub})
	}()
	go func() {
		src, _ := os.Open("./test/user.priv")
		stat, _ := src.Stat()
		priSize = stat.Size()
		priHash, _ = crypto.CalFileHash(src)
		userNode.Upload(src, "/", "test", priHash, priSize, []p2pCrypto.PubKey{seaPub})
	}()
	time.Sleep(5 * time.Second)
}

func TestDownload(t *testing.T) {
	go userNode.SendDownloadProtocol(seaPeer, "./test/", pubHash, pubSize)
	go userNode.SendDownloadProtocol(seaPeer, "./test/", priHash, priSize)
	time.Sleep(5 * time.Second)
}
