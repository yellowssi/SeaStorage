package crypto

import (
	"fmt"
	"gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"os"
	"testing"
)

var key = crypto.GenerateRandomAESKey(lib.AESKeySize)

func init() {
	if _, err := os.Stat("./test"); os.IsNotExist(err) {
		lib.GenerateKey("test", "./test/")
	}
}

func TestEncryptFile(t *testing.T) {
	inFile, err := os.Open("./test/test.priv")
	if err != nil {
		t.Error(err)
	}
	outFile, err := os.OpenFile("./test/test.enc", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Error(err)
	}
	hash, err := EncryptFile(inFile, outFile, key)
	if err != nil {
		t.Error(err)
	}
	t.Log(hash)
}

func TestDecryptFile(t *testing.T) {
	inFile, err := os.Open("./test/test.enc")
	if err != nil {
		t.Error(err)
	}
	outFile, err := os.OpenFile("./test/test_result.priv", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Error(err)
	}
	hash, err := DecryptFile(inFile, outFile, key)
	if err != nil {
		t.Error(err)
	}
	t.Log(hash)
}

func TestCalFileHash(t *testing.T) {
	f, err := os.Open("./test/test.enc")
	if err != nil {
		t.Error(err)
	}
	hash, err := CalFileHash(f)
	if err != nil {
		t.Error(err)
	}
	t.Log(hash)
}

func TestSplitFile(t *testing.T) {
	inFile, err := os.Open("./test/test.priv")
	if err != nil {
		t.Error(err)
	}
	hashes, err := SplitFile(inFile, "./test", lib.DefaultDataShards, lib.DefaultParShards)
	if err != nil {
		t.Error(err)
	}
	t.Log(hashes)
}

func TestMergeFile(t *testing.T) {
	outFile, err := os.OpenFile("./test/test_merge.priv", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Error(err)
	}
	hashes := make([]string, lib.DefaultDataShards+lib.DefaultParShards)
	for i := range hashes {
		hashes[i] = fmt.Sprintf("%s.%d", "test.priv", i)
	}
	err = MergeFile("./test", hashes, outFile, 64, lib.DefaultDataShards, lib.DefaultParShards)
	if err != nil {
		t.Error(err)
	}
}

func TestGenerateFileInfo(t *testing.T) {
	info, err := GenerateFileInfo("./test/test.priv", 5, 3)
	if err != nil {
		t.Error(err)
	}
	t.Log(info)
}
