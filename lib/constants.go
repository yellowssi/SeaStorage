// Copyright © 2019 yellowsea <hh1271941291@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lib

import (
	"crypto/aes"
	"os/user"
	"path"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
)

var (
	// TPURL is the Hyperledger Sawtooth rest api url.
	TPURL string
	// ValidatorURL is the Hyperledger Sawtooth validator tcp url.
	ValidatorURL string
	// StoragePath is the path that provided storage resources by sea.
	StoragePath string
	// StorageSize is the limit size of the storage resources.
	StorageSize int64
	// ListenAddress is the address used for joining P2P network and listening for protobuf.
	ListenAddress string
	// ListenPort is the port for the P2P Network protobuf listener.
	ListenPort int
	// BootstrapAddrs is the addresses in the P2P Network. These addresses are using for node joining P2P Network.
	BootstrapAddrs []ma.Multiaddr
)

const (
	// Config Variable

	// FamilyName is the SeaStorage's transaction identity.
	FamilyName string = "SeaStorage"
	// FamilyVersion is the version of SeaStorage's transaction.
	FamilyVersion string = "1.0"
	// DefaultTmpPath is used for storing temp file.
	DefaultTmpPath string = "/tmp/SeaStorage"
	// DefaultWait is the waiting time for batch commits.
	DefaultWait = time.Minute
	// DefaultQueryLimit is the limit of state queries.
	DefaultQueryLimit uint = 20
	// EncryptSuffix is the encrypted file's suffix.
	EncryptSuffix string = ".enc"
	// DefaultConfigFilename is the config filename.
	DefaultConfigFilename string = "config"
	// PackageSize is the limit of each package's max size.
	PackageSize int64 = 128 * 1024 * 1024

	// Content types

	// ContentTypeOctetStream is the content type for request.
	ContentTypeOctetStream string = "application/octet-stream"
	// ContentTypeJSON is the content type for request.
	ContentTypeJSON string = "application/json"

	// APIs

	// BatchSubmitAPI is the api for batch submission.
	BatchSubmitAPI string = "batches"
	// BatchStatusAPI is the api for getting batches' status.
	BatchStatusAPI string = "batch_statuses"
	// StateAPI is the api for getting data stored in the blockchain.
	StateAPI string = "state"
	// AES-CTR

	// AESKeySize is the size of AES key.
	AESKeySize int = 256
	// IvSize is the AES-CTR iv's size.
	IvSize = aes.BlockSize
	// BufferSize is the size for encryption.
	BufferSize = 4096
)

var (
	// Logger provides log function.
	Logger *logrus.Logger
	// DefaultTPURL is the default Hyperledger Sawtooth rest api url.
	DefaultTPURL = "http://101.132.168.252:8008"
	// DefaultValidatorURL is the default Hyperledger Sawtooth validator tcp url.
	DefaultValidatorURL = "tcp://101.132.168.252:4004"
	// DefaultListenAddress is the default listen address for P2P network node.
	DefaultListenAddress = "0.0.0.0"
	// DefaultListenPort is the default listen port for P2P network node.
	DefaultListenPort = 5001
	// PrivateKeyFile is the path of private key.
	PrivateKeyFile string
	// DefaultKeyPath is the default path for key storing.
	DefaultKeyPath string
	// DefaultPrivateKeyFile is the default path of private key.
	DefaultPrivateKeyFile string
	// DefaultConfigPath is the default path for config storing.
	DefaultConfigPath string
	// DefaultLogPath is the default path for log storing.
	DefaultLogPath string
	// DefaultLargeFileSize is the limit of max file size for RS erasure coding using.
	DefaultLargeFileSize int64 = 1024 * 1024 * 1024
	// DefaultDataShards is the number of data shard in RS erasure coding.
	DefaultDataShards = 5
	// DefaultParShards is the number of parity shard in RS erasure coding.
	DefaultParShards = 3
	// DefaultStoragePath is the default path for providing storage resources.
	DefaultStoragePath string
	// DefaultStorageSize is the default limit size of storage resources.
	DefaultStorageSize int64 = 1024 * 1024 * 1024
	// DefaultBootstrapAddrs is the default addresses for joining P2P network.
	DefaultBootstrapAddrs = []string{
		"/ip4/129.204.249.51/tcp/5001/p2p/16Uiu2HAkwxu3JAoqZ7QQ343hQuADCbkqfimCNRTnqQgoUpvoKEty",
		"/ip4/101.132.168.252/tcp/5001/p2p/16Uiu2HAmHoT7LJpqYhZfLddG6Gu7WBkHh44cMiGp1FgCjPjbhEkA",
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
	DefaultPrivateKeyFile = path.Join(DefaultKeyPath, "SeaStorage.priv")
	DefaultStoragePath = path.Join(DefaultConfigPath, "storage")
	DefaultLogPath = path.Join(DefaultConfigPath, "log")
}
