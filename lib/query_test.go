package lib

import "testing"

func init() {
	TPURL = DefaultTPURL
}

func TestListSeasPublicKey(t *testing.T) {
	seas, err := ListSeasPublicKey("", 0)
	if err != nil {
		t.Error(err)
	}
	t.Log(seas)
}
