package crypto

import (
	"gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"gitlab.com/SeaStorage/SeaStorage/lib"
	"os"
	"testing"
)

var key = crypto.GenerateRandomAESKey(lib.AESKeySize)

func init() {
	if _, err := os.Stat("./key"); os.IsNotExist(err) {
		lib.GenerateKey("test", "./key/")
	}
}

func TestEncryptFile(t *testing.T) {
	inFile, err := os.Open("./key/test.priv")
	if err != nil {
		t.Error(err)
	}
	outFile, err := os.OpenFile("./key/test.enc", os.O_CREATE|os.O_WRONLY, 0644)
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
	inFile, err := os.Open("./key/test.enc")
	if err != nil {
		t.Error(err)
	}
	outFile, err := os.OpenFile("./key/test_result.priv", os.O_CREATE|os.O_WRONLY, 0644)
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
	f, err := os.Open("./key/test.enc")
	if err != nil {
		t.Error(err)
	}
	hash, err := CalFileHash(f)
	if err != nil {
		t.Error(err)
	}
	t.Log(hash)
}

func TestSliceEncodeFile(t *testing.T) {
	f, err := os.Open("./key/test.priv")
	if err != nil {
		t.Error(err)
	}
	hashes, err := SplitFile(f, "./key", 5, 3)
	if err != nil {
		t.Error(err)
	}
	t.Log(hashes)
}

func TestSliceDecodeFile(t *testing.T) {
	outFile, err := os.OpenFile("./key/test.merge.priv", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Error(err)
	}
	hashes, err := MergeFile("./key", "test.priv", outFile, 5, 3)
	if err != nil {
		t.Error(err)
	}
	t.Log(hashes)
}

func TestGenerateFileInfo(t *testing.T) {
	info, err := GenerateFileInfo("./key/test.priv", 5, 3)
	if err != nil {
		t.Error(err)
	}
	t.Log(info)
}
