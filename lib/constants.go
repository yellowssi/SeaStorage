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

	ma "github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
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
	FamilyName            string = "SeaStorage"
	FamilyVersion         string = "1.0.0"
	DefaultTmpPath        string = "/tmp/SeaStorage"
	DefaultWait           uint   = 60
	AESKeySize            int    = 256
	EncryptSuffix         string = ".enc"
	DefaultDataShards     int    = 5
	DefaultParShards      int    = 3
	DefaultConfigFilename string = "config"
	PackageSize           int64  = 128 * 1024 * 1024
	BigFileSize           int64  = 1024 * 1024 * 1024
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
	DefaultTPURL                = "http://101.132.168.252:8008"
	DefaultStorageSize    int64 = 1024 * 1024 * 1024
	DefaultListenAddress        = "0.0.0.0"
	DefaultListenPort           = 5001
	KeyFile               string
	DefaultKeyPath        string
	DefaultKeyFile        string
	DefaultConfigPath     string
	DefaultStoragePath    string
	DefaultLogPath        string
	DefaultBootstrapAddrs = []string{
		"/ip4/129.204.249.51/tcp/5001/p2p/16Uiu2HAkwxu3JAoqZ7QQ343hQuADCbkqfimCNRTnqQgoUpvoKEty",
		"/ip4/101.132.168.252/tcp/5001/p2p/16Uiu2HAmHoT7LJpqYhZfLddG6Gu7WBkHh44cMiGp1FgCjPjbhEkA",
		//"/ip4/192.168.31.99/tcp/5001/p2p/16Uiu2HAm2Ckrip9389C25mrcMrMRDxeasADmd2sGgcLBbgfTD8F2",
		//"/ip4/192.168.31.200/tcp/5001/p2p/16Uiu2HAkyEDMPbbAwVSoC6nav6bsCKM13C5D1TBDEZwSr4pkg3WR",
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
	DefaultKeyFile = path.Join(DefaultKeyPath, "SeaStorage.priv")
	DefaultStoragePath = path.Join(DefaultConfigPath, "storage")
	DefaultLogPath = path.Join(DefaultConfigPath, "log")
}
