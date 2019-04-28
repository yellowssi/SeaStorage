package lib

import (
	"os"
	"testing"
)

var c *ClientFramework

func init() {
	if _, err := os.Stat("./key"); os.IsNotExist(err) {
		GenerateKey("test", "./key/")
	}
	c, _ = NewClient("Test", ClientCategoryUser, "http://localhost:8008", "./key/test.priv")
}

func TestClientFramework_Register(t *testing.T) {
	_, err := c.Register("Test")
	if err != nil {
		t.Error(err)
	}
}

func TestClientFramework_Show(t *testing.T) {
	u, err := c.Show()
	if err != nil {
		t.Error(err)
	}
	t.Log(u)
}

func TestClientFramework_ListAll(t *testing.T) {
	response, err := c.ListAll("", 0)
	if err != nil {
		t.Error(err)
	}
	if len(response) > 0 {
		t.Log(response[0].(map[string]interface{}))
	}
}
