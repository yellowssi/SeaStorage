package user

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gitlab.com/SeaStorage/SeaStorage/lib"
)

var cli *Client
var err error

func init() {
	lib.Logger = logrus.New()
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
	lib.GenerateKey("test", "test")
	//lib.TPURL = lib.DefaultTPURL
	lib.TPURL = "http://127.0.0.1:8008"
	//lib.ListenAddress = lib.DefaultListenAddress
	lib.ListenAddress = "192.168.31.200"
	lib.ListenPort = lib.DefaultListenPort
	cli, err = NewUserClient("test", "./test/test.priv", lib.BootstrapAddrs)
	if err != nil {
		panic(err)
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
	response, err := cli.CreateDirectory("/home/SeaStorage")
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}

func TestClient_GetINode(t *testing.T) {
	iNode, err := cli.GetINode("/home/SeaStorage")
	if err != nil {
		t.Error(err)
	}
	t.Log(iNode)
}

func TestClient_CreateFile(t *testing.T) {
	response, err := cli.CreateFile("/etc/hostname", "/home/SeaStorage", lib.DefaultDataShards, lib.DefaultParShards)
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
	time.Sleep(5 * time.Second)
}

func TestClient_DownloadFiles(t *testing.T) {
	cli.DownloadFiles("/home/SeaStorage/hostname", "./test")
	time.Sleep(5 * time.Second)
}

func TestClient_DeleteFile(t *testing.T) {
	response, err := cli.DeleteFile("/home/SeaStorage/hostname")
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}

func TestClient_DeleteDirectory(t *testing.T) {
	response, err := cli.DeleteDirectory("/home")
	if err != nil {
		t.Error(err)
	}
	t.Log(response)
}
