package p2p

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	p2pCrypto "github.com/libp2p/go-libp2p-core/crypto"
	p2pPeer "github.com/libp2p/go-libp2p-core/peer"
	p2pPeerstore "github.com/libp2p/go-libp2p-core/peer"
	p2pDHT "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	tpCrypto "github.com/yellowssi/SeaStorage-TP/crypto"
	"github.com/yellowssi/SeaStorage/crypto"
	"github.com/yellowssi/SeaStorage/lib"
)

var userCli, seaCli *lib.ClientFramework
var userNode *UserNode
var seaPeer p2pPeer.ID
var seaPub string
var pubHash string
var pubSize int64

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
	seaPub = string(seaPubBytes)
	seaCtx := context.Background()
	seaHost, _ := libp2p.New(seaCtx, libp2p.ListenAddrs(seaAddr), libp2p.Identity(seaPriv))
	seaPeer = seaHost.ID()
	_, _ = NewSeaNode(seaCli, "./test", lib.DefaultStorageSize, seaHost)
	userCli, _ = lib.NewClientFramework("test", lib.ClientCategoryUser, "./test/user.priv")
	userAddr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6666")
	userPrivBytes, _ := ioutil.ReadFile("./test/user.priv")
	userPriv, _ := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(userPrivBytes)))
	userCtx := context.Background()
	userHost, _ := libp2p.New(userCtx, libp2p.ListenAddrs(userAddr), libp2p.Identity(userPriv))
	kadDHT, _ := p2pDHT.New(userCtx, userHost)
	_ = kadDHT.Bootstrap(userCtx)
	sma, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6667/p2p/" + seaPeer.String())
	seaInfo, _ := p2pPeerstore.AddrInfoFromP2pAddr(sma)
	_ = userHost.Connect(userCtx, *seaInfo)
	userNode = NewUserNode(userHost, userCli)
}

func TestUpload(t *testing.T) {
	src, _ := os.Open("./test/user.pub")
	stat, _ := src.Stat()
	pubSize = stat.Size()
	pubHash, _ = crypto.CalFileHash(src)
	userNode.Upload(src, "/", "test", pubHash, pubSize, []string{seaPub})
	time.Sleep(5 * time.Second)
}

func TestDownload(t *testing.T) {
	go userNode.SendDownloadProtocol(seaPeer, "./test/", "", pubHash, pubSize)
	time.Sleep(5 * time.Second)
}
