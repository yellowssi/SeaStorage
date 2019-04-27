package lib

import "crypto/aes"

const (
	// String literals
	CommandName      string = "sst"
	FamilyName       string = "SeaStorage"
	FamilyVersion    string = "1.0"
	DistributionName string = "SeaStorage-ClientFramework"
	DefaultUrl       string = "http://127.0.0.1:8008"
	DefaultWait      uint   = 60
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
	HmacSize   = 32
)
