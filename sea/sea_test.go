package sea

import (
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"testing"
)

var sea *Client

func init() {
	lib.TPURL = lib.DefaultTPURL
	lib.ListenAddress = "127.0.0.1"
	lib.ListenPort = 55555
	lib.GenerateKey("sea", "test")
	sea, _ = NewSeaClient("test", "./test/sea.priv")
}

func TestClient_SeaRegister(t *testing.T) {
	err := sea.SeaRegister()
	if err != nil {
		t.Fatal(err)
	}
}
