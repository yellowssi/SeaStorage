package lib

import "crypto/aes"

const (
	// String literals
	FamilyName           string = "SeaStorage"
	FamilyVersion        string = "1.0.0"
	DefaultListenAddress string = "0.0.0.0"
	DefaultListenPort    int    = 5001
	DefaultStoragePath   string = "/var/lib/SeaStorage"
	DefaultStorageSize   int64  = 1024 * 1024 * 1024
	DefaultTmpPath       string = "/tmp/SeaStorage"
	DefaultWait          uint   = 60
	AESKeySize           int    = 256
	EncryptSuffix        string = ".enc"
	DefaultDataShards    int    = 5
	DefaultParShards     int    = 3
	// Content types
	ContentTypeOctetStream string = "application/octet-stream"
	ContentTypeJson        string = "application/json"
	// APIs
	BatchSubmitApi string = "batches"
	BatchStatusApi string = "batch_statuses"
	StateApi       string = "state"
	// AES CTR
	IvSize      = aes.BlockSize
	BufferSize  = 4096
	PackageSize = 134217728
)

var (
	TPURL = "http://127.0.0.1:8008"
)
