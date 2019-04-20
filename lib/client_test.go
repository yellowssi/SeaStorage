package lib

import (
	"os"
	"testing"
)

var c Client

func init() {
	if _, err := os.Stat("./key"); os.IsNotExist(err) {
		GenerateKey("test", "./key/")
	}
	c, _ = NewClient("Test", "User", "http://localhost:8008", "./key/test.priv")
}

func TestClient_SendTransaction(t *testing.T) {
	err := c.Register("Test")
	if err != nil {
		t.Error(err)
	}
}

func TestClient_Show(t *testing.T) {
	u, err := c.Show()
	if err != nil {
		t.Error(err)
	}
	t.Log(u)
}

func TestClient_List(t *testing.T) {
	response, err := c.List("", 0)
	if err != nil {
		t.Error(err)
	}
	t.Log(response[0].(map[interface{}]interface{}))
}
