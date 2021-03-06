package crypto

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	tpCrypto "github.com/yellowssi/SeaStorage-TP/crypto"
	"github.com/yellowssi/SeaStorage/lib"
)

var key = tpCrypto.GenerateRandomAESKey(lib.AESKeySize)

func init() {
	lib.GenerateKey("test", "./test/")
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
	hashes, size, err := SplitFile(inFile, "./test", lib.DefaultDataShards, lib.DefaultParShards)
	if err != nil {
		t.Error(err)
	}
	t.Log("size:", size)
	t.Log("hashes:", hashes)
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
	publicKeyBytes, _ := ioutil.ReadFile("./test/test.pub")
	keyAES := tpCrypto.GenerateRandomAESKey(lib.AESKeySize)
	info, err := GenerateFileInfo("./test/test.priv", string(publicKeyBytes), tpCrypto.BytesToHex(keyAES), 5, 3)
	if err != nil {
		t.Error(err)
	}
	data, _ := json.Marshal(info)
	t.Log(string(data))
}
