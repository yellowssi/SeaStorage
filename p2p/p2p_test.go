package p2p

import (
	"testing"
)

func TestDirSize(t *testing.T) {
	size, _ := dirSize("/etc")
	t.Log(size)
}
