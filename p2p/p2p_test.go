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

var userCli, sea1Cli, sea2Cli *lib.ClientFramework
var userNode *UserNode
var sea1Peer, sea2Peer p2pPeer.ID
var sea1Pub, sea2Pub string
var pubHash string
var pubSize int64
var sea1Kad, sea2Kad, userKad *p2pDHT.IpfsDHT

func init() {
	lib.Logger = logrus.New()
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
	lib.GenerateKey("sea1", "test")
	lib.GenerateKey("sea2", "test")
	lib.GenerateKey("user", "test")
	// Sea 1
	sea1Cli, _ = lib.NewClientFramework("test", lib.ClientCategorySea, "./test/sea1.priv")
	seaAddr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6667")
	seaPrivBytes, _ := ioutil.ReadFile("./test/sea1.priv")
	seaPriv, _ := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(seaPrivBytes)))
	seaPubBytes, _ := ioutil.ReadFile("./test/sea1.pub")
	sea1Pub = string(seaPubBytes)
	seaCtx := context.Background()
	seaHost, _ := libp2p.New(seaCtx, libp2p.ListenAddrs(seaAddr), libp2p.Identity(seaPriv))
	sea1Peer = seaHost.ID()
	sea1Kad, _ = p2pDHT.New(seaCtx, seaHost)
	_ = sea1Kad.Bootstrap(seaCtx)
	_, _ = NewSeaNode(seaCtx, sea1Cli, "./test", lib.DefaultStorageSize, seaHost, sea1Kad)
	// Sea 2
	sea2Cli, _ = lib.NewClientFramework("test", lib.ClientCategorySea, "./test/sea2.priv")
	sea2Addr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6668")
	sea2PrivBytes, _ := ioutil.ReadFile("./test/sea2.priv")
	sea2Priv, _ := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(sea2PrivBytes)))
	sea2PubBytes, _ := ioutil.ReadFile("./test/sea2.pub")
	sea2Pub = string(sea2PubBytes)
	sea2Ctx := context.Background()
	sea2Host, _ := libp2p.New(sea2Ctx, libp2p.ListenAddrs(sea2Addr), libp2p.Identity(sea2Priv))
	sea2Peer = sea2Host.ID()
	sea2Kad, _ = p2pDHT.New(sea2Ctx, sea2Host)
	_ = sea2Kad.Bootstrap(sea2Ctx)
	sea1Ma, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6667/p2p/" + sea1Peer.String())
	sea1Info, _ := p2pPeerstore.AddrInfoFromP2pAddr(sea1Ma)
	_ = sea2Host.Connect(sea2Ctx, *sea1Info)
	_, _ = NewSeaNode(sea2Ctx, sea2Cli, "./test", lib.DefaultStorageSize, sea2Host, sea2Kad)
	userCli, _ = lib.NewClientFramework("test", lib.ClientCategoryUser, "./test/user.priv")
	userAddr, _ := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/6666")
	userPrivBytes, _ := ioutil.ReadFile("./test/user.priv")
	userPriv, _ := p2pCrypto.UnmarshalSecp256k1PrivateKey(tpCrypto.HexToBytes(string(userPrivBytes)))
	userCtx := context.Background()
	userHost, _ := libp2p.New(userCtx, libp2p.ListenAddrs(userAddr), libp2p.Identity(userPriv))
	userKad, _ = p2pDHT.New(userCtx, userHost)
	_ = userKad.Bootstrap(userCtx)
	_ = userHost.Connect(userCtx, *sea1Info)
	userNode = NewUserNode(userCtx, userHost, userKad, userCli)
}

func TestUpload(t *testing.T) {
	src, _ := os.Open("./test/user.pub")
	stat, _ := src.Stat()
	pubSize = stat.Size()
	pubHash, _ = crypto.CalFileHash(src)
	userNode.Upload(src, "/", "test", pubHash, pubSize, []string{sea1Pub, sea2Pub})
	time.Sleep(1 * time.Second)
}

func TestDownload(t *testing.T) {
	go userNode.SendDownloadProtocol(sea1Peer, "./test/", "", pubHash, pubSize)
	time.Sleep(1 * time.Second)
}

func TestFindPeer(t *testing.T) {
	result, err := userKad.FindPeer(context.Background(), sea2Peer)
	if err != nil {
		t.Log(err)
	}
	t.Log(result)
}
