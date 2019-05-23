package lib

import (
	"crypto/aes"
	"github.com/sirupsen/logrus"
	"os/user"
	"path"

	ma "github.com/multiformats/go-multiaddr"
)

var (
	TPURL          string
	StoragePath    string
	StorageSize    int64
	ListenAddress  string
	ListenPort     int
	BootstrapAddrs []ma.Multiaddr
)

const (
	// Config Variable
	FamilyName           string = "SeaStorage"
	FamilyVersion        string = "1.0.0"
	DefaultTmpPath       string = "/tmp/SeaStorage"
	DefaultWait          uint   = 60
	AESKeySize           int    = 256
	EncryptSuffix        string = ".enc"
	DefaultDataShards    int    = 5
	DefaultParShards     int    = 3
	DefaultTPURL         string = "http://129.204.249.51:8008"
	DefaultStorageSize   int64  = 1024 * 1024 * 1024
	DefaultListenAddress string = "0.0.0.0"
	DefaultListenPort    int    = 5001
	PackageSize          int64  = 134217728
	// Content types
	ContentTypeOctetStream string = "application/octet-stream"
	ContentTypeJson        string = "application/json"
	// APIs
	BatchSubmitApi string = "batches"
	BatchStatusApi string = "batch_statuses"
	StateApi       string = "state"
	// AES CTR
	IvSize     = aes.BlockSize
	BufferSize = 4096
)

var (
	Logger                *logrus.Logger
	DefaultKeyPath        string
	DefaultConfigPath     string
	DefaultStoragePath    string
	DefaultLogPath        string
	DefaultBootstrapAddrs = []string{
		"/ip4/129.204.249.51/tcp/5001/p2p/16Uiu2HAkwxu3JAoqZ7QQ343hQuADCbkqfimCNRTnqQgoUpvoKEty",
	}
)

func init() {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	homeDir := u.HomeDir
	DefaultConfigPath = path.Join(homeDir, ".SeaStorage")
	DefaultKeyPath = path.Join(DefaultConfigPath, "keys")
	DefaultStoragePath = path.Join(DefaultConfigPath, "storage")
	DefaultLogPath = path.Join(DefaultConfigPath, "log")
}
