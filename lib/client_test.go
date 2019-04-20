package lib

import (
	"os"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	if _, err := os.Stat("./key"); os.IsNotExist(err) {
		GenerateKey("test", "./key/")
	}
}

func TestClient_SendTransaction(t *testing.T) {
	c, err := NewClient("", "User", "http://localhost:8008", "./key/test.priv")
	if err != nil {
		t.Error(err)
	}
	err = c.Register("Test")
	if err != nil {
		t.Error(err)
	}
}

func TestClient_Show(t *testing.T) {
	c, err := NewClient("Test", "User", "http://localhost:8008", "./key/test.priv")
	if err != nil {
		t.Error(err)
	}
	u, err := c.Show()
	if err != nil {
		t.Error(err)
	}
	t.Log(u)
}
