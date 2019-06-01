package user

import (
	"os"
	"path"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
	"github.com/yellowssi/SeaStorage/lib"
)

var cli *Client
var err error

func init() {
	lib.Logger = logrus.New()
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
	lib.GenerateKey("test", "test")
	lib.TPURL = lib.DefaultTPURL
	lib.ListenAddress = lib.DefaultListenAddress
	lib.ListenPort = lib.DefaultListenPort
	InitAddrs(lib.DefaultBootstrapAddrs)
	cli, err = NewUserClient("test", "./test/test.priv", lib.BootstrapAddrs)
	if err != nil {
		panic(err)
	}
}

func InitAddrs(bootstrapAddrs []string) {
	for _, addr := range bootstrapAddrs {
		multiaddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			lib.Logger.WithFields(logrus.Fields{
				"peer": addr,
			}).Warn("failed to init peer addr")
		}
		lib.BootstrapAddrs = append(lib.BootstrapAddrs, multiaddr)
	}
}

func TestClient_Register(t *testing.T) {
	err := cli.UserRegister()
	if err != nil {
		t.Error(err)
	}
	t.Log("User: ", cli.User)
	t.Log("PWD: ", cli.PWD)
}

func TestClient_ChangePWD(t *testing.T) {
	t.Log(path.Join("/a/b/c", "/d", ".", "a"))
}

func TestClient_CreateDirectory(t *testing.T) {
	response, err := cli.CreateDirectory("/SeaStorage")
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}

func TestClient_GetINode(t *testing.T) {
	iNode, err := cli.GetINode("/SeaStorage")
	if err != nil {
		t.Error(err)
	}
	t.Log(iNode)
}

func TestClient_CreateFile(t *testing.T) {
	response, err := cli.CreateFile("/etc/hostname", "/SeaStorage", lib.DefaultDataShards, lib.DefaultParShards)
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
	time.Sleep(2 * time.Minute)
}

func TestClient_DownloadFiles(t *testing.T) {
	cli.DownloadFiles("/SeaStorage/hostname", "./test")
	time.Sleep(5 * time.Second)
}

func TestClient_DeleteFile(t *testing.T) {
	response, err := cli.DeleteFile("/SeaStorage/hostname")
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}

func TestClient_DeleteDirectory(t *testing.T) {
	response, err := cli.DeleteDirectory("/SeaStorage")
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}
