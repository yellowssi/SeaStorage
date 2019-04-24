package user

import (
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"path"
	"testing"
)

var cli *Client

func init() {
	cli, _ = NewUserClient("Test", lib.DefaultUrl, "../lib/key/test.priv")
}

func TestClient_Register(t *testing.T) {
	err := cli.Register()
	if err != nil {
		t.Error(err)
	}
	t.Log("User: ", cli.User)
	t.Log("PWD: ", cli.PWD)
}

func TestClient_ChangePWD(t *testing.T) {
	t.Log(path.Join("/a/b/c", "..", ".", "d"))
}
