package lib

import "crypto/aes"

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
	DefaultTPURL         string = "http://127.0.0.1:8008"
	DefaultStoragePath   string = "/var/lib/SeaStorage"
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
	TPURL         string
	StoragePath   string
	StorageSize   int64
	ListenAddress string
	ListenPort    int
)
