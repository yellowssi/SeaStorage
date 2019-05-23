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

var cli *lib.ClientFramework
var seaNode *SeaNode
var userNode *UserNode
var seaPeer p2pPeer.ID
var userPeer p2pPeer.ID
var hash string
var size int64

func init() {
	lib.Logger = logrus.New()
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
	lib.StoragePath = lib.DefaultStoragePath
	lib.GenerateKey("sea", "test")
	lib.GenerateKey("user", "test")
	cli, _ = lib.NewClientFramework("test", lib.ClientCategorySea, "./test/sea.priv")
	seaAddr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6667")
	seaPrivBytes, _ := ioutil.ReadFile("./test/sea.priv")
	seaPriv, _ := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(seaPrivBytes)))
	seaCtx := context.Background()
	seaHost, _ := libp2p.New(seaCtx, libp2p.ListenAddrs(seaAddr), libp2p.Identity(seaPriv))
	seaPeer = seaHost.ID()
	seaNode, _ = NewSeaNode(cli, lib.DefaultStoragePath, lib.DefaultStorageSize, seaHost)
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
	userNode = NewUserNode(userHost)
}

func TestUpload(t *testing.T) {
	src, _ := os.Open("./test/user.pub")
	stat, _ := src.Stat()
	size = stat.Size()
	hash, _ = crypto.CalFileHash(src)
	operation := cli.GenerateOperation("/", "test", hash, size)
	err := userNode.Upload(src, operation, []p2pPeer.ID{seaPeer})
	if err != nil {
		t.Error(err)
	}
	time.Sleep(5 * time.Second)
}

func TestDownload(t *testing.T) {
	userNode.SendDownloadProtocol(seaPeer, "./test/", hash, size)
	time.Sleep(5 * time.Second)
}
