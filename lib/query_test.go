package lib

import "testing"

func init() {
	TPURL = DefaultTPURL
}

func TestListSeasPeerId(t *testing.T) {
	seas, err := ListSeasPeerId("", 0)
	if err != nil {
		t.Error(err)
	}
	t.Log(seas[0])
}
