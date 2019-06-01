package lib

import (
	"os"
	"testing"

	tpUser "github.com/yellowssi/SeaStorage-TP/user"
)

var c *ClientFramework

func init() {
	if _, err := os.Stat("./test"); os.IsNotExist(err) {
		GenerateKey("test", "./test/")
	}
	c, _ = NewClientFramework("Test", ClientCategoryUser, "./test/test.priv")
}

func TestClientFramework_Register(t *testing.T) {
	_, err := c.Register("Test")
	if err != nil {
		t.Error(err)
	}
}

func TestClientFramework_Show(t *testing.T) {
	u, err := c.GetData()
	if err != nil {
		t.Error(err)
	}
	t.Log(tpUser.UserFromBytes(u))
}

func TestListAll(t *testing.T) {
	response, err := ListAll("", 0)
	if err != nil {
		t.Error(err)
	}
	if len(response) > 0 {
		t.Log(response[0].(map[string]interface{}))
	}
}
