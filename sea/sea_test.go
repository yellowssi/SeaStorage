package sea

import (
	"testing"

	"github.com/yellowssi/SeaStorage/lib"
)

var sea *Client

func init() {
	lib.TPURL = lib.DefaultTPURL
	lib.ListenAddresses = lib.DefaultListenAddresses
	lib.GenerateKey("sea", "test")
	sea, _ = NewSeaClient("test", "./test/sea.priv")
}

func TestClient_SeaRegister(t *testing.T) {
	err := sea.SeaRegister()
	if err != nil {
		t.Fatal(err)
	}
}
