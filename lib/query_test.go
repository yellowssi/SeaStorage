package lib

import "testing"

func init() {
	TPURL = "http://127.0.0.1:8008"
	//TPURL = DefaultTPURL
}

func TestListSeasPublicKey(t *testing.T) {
	seas, err := ListSeasPublicKey("", 0)
	if err != nil {
		t.Error(err)
	}
	t.Log(seas)
}
