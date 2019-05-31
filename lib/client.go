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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/batch_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/transaction_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/signing"
	tpCrypto "gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	tpPayload "gitlab.com/SeaStorage/SeaStorage-TP/payload"
	tpState "gitlab.com/SeaStorage/SeaStorage-TP/state"
	tpUser "gitlab.com/SeaStorage/SeaStorage-TP/user"
)

// The Category of ClientFramework.
const (
	ClientCategoryUser = true
	ClientCategorySea  = false
)

// The status of Hyperledger Sawtooth transaction.
const (
	StatusPending   = "PENDING"
	StatusCommitted = "COMMITTED"
	StatusInvalid   = "INVALID"
)

// The error response of Hyperledger Sawtooth transaction.
var (
	errWaitingForCommitted = errors.New("waiting for committed")
	errInvalidTransaction  = errors.New("invalid transaction")
)

// ClientFramework provides SeaStorage base operations for both user and sea.
type ClientFramework struct {
	Name     string // The name of user or sea.
	Category bool   // The category of client framework.
	signer   *signing.Signer
}

// NewClientFramework is the construct for ClientFramework.
func NewClientFramework(name string, category bool, keyFile string) (*ClientFramework, error) {
	if name == "" {
		return nil, errors.New("need a valid name")
	}
	if keyFile == "" {
		return nil, errors.New("need a valid key")
	}
	// Read private key file
	privateKeyHex, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}
	// Get private key object
	privateKey := signing.NewSecp256k1PrivateKey(tpCrypto.HexToBytes(string(privateKeyHex)))
	cryptoFactory := signing.NewCryptoFactory(signing.NewSecp256k1Context())
	signer := cryptoFactory.NewSigner(privateKey)
	return &ClientFramework{Name: name, Category: category, signer: signer}, nil
}

// Register user or sea. Create user or sea in the blockchain.
func (cf *ClientFramework) Register(name string) (map[string]interface{}, error) {
	var seaStoragePayload tpPayload.SeaStoragePayload
	if cf.Category {
		seaStoragePayload.Action = tpPayload.CreateUser
	} else {
		seaStoragePayload.Action = tpPayload.CreateSea
	}
	seaStoragePayload.Target = []string{name}
	cf.Name = name
	response, err := cf.SendTransaction([]tpPayload.SeaStoragePayload{seaStoragePayload}, []string{cf.GetAddress()}, []string{cf.GetAddress()}, 0)
	if err != nil {
		return nil, err
	}
	if cf.waitingForRegister(60) {
		return response, nil
	}
	return response, errWaitingForCommitted
}

// GetData returns the data of user or sea.
func (cf *ClientFramework) GetData() ([]byte, error) {
	return GetStateData(cf.GetAddress())
}

// GetAddress returns the address of user or sea.
func (cf *ClientFramework) GetAddress() string {
	if cf.Category {
		return tpState.MakeAddress(tpState.AddressTypeUser, cf.Name, cf.signer.GetPublicKey().AsHex())
	}
	return tpState.MakeAddress(tpState.AddressTypeSea, cf.Name, cf.signer.GetPublicKey().AsHex())
}

// GetPublicKey returns the public key of user or sea.
func (cf *ClientFramework) GetPublicKey() string {
	return cf.signer.GetPublicKey().AsHex()
}

// GenerateOperation return the user operation signed by user's private key.
func (cf *ClientFramework) GenerateOperation(sea, path, name, hash string, size int64) *tpUser.Operation {
	packages := time.Duration(math.Ceil(float64(size) / float64(PackageSize)))
	timestamp := time.Now().Add(packages * time.Hour).Unix()
	return tpUser.NewOperation(cf.GetAddress(), cf.signer.GetPublicKey().AsHex(), sea, path, name, hash, size, timestamp, *cf.signer)
}

// Whoami display the information of user or sea.
func (cf *ClientFramework) Whoami() {
	if cf.Category {
		fmt.Println("User name: " + cf.Name)
	} else {
		fmt.Println("Sea name: " + cf.Name)
	}
	fmt.Println("Public key: " + cf.signer.GetPublicKey().AsHex())
	fmt.Println("Sawtooth address: " + cf.GetAddress())
}

// DecryptFileKey returns the key decrypted by user's private key.
// If the error is not nil, it will return.
func (cf *ClientFramework) DecryptFileKey(key string) ([]byte, error) {
	privateKey, _ := ioutil.ReadFile(PrivateKeyFile)
	return tpCrypto.Decryption(string(privateKey), key)
}

// GetStatus returns the status of batch.
func (cf *ClientFramework) getStatus(batchID string, wait uint) (map[string]interface{}, error) {
	// API to call
	apiSuffix := fmt.Sprintf("%s?id=%s&wait=%d", BatchStatusAPI, batchID, wait)
	response, err := sendRequestByAPISuffix(apiSuffix, []byte{}, "")
	if err != nil {
		return nil, err
	}

	entry := response["data"].([]interface{})[0].(map[string]interface{})
	return entry, nil
}

// SendTransaction send transactions by the batch.
func (cf *ClientFramework) SendTransaction(seaStoragePayloads []tpPayload.SeaStoragePayload, inputs, outputs []string, wait uint) (map[string]interface{}, error) {
	var transactions []*transaction_pb2.Transaction

	for _, seaStoragePayload := range seaStoragePayloads {
		// Construct TransactionHeader
		rawTransactionHeader := transaction_pb2.TransactionHeader{
			SignerPublicKey:  cf.signer.GetPublicKey().AsHex(),
			FamilyName:       FamilyName,
			FamilyVersion:    FamilyVersion,
			Dependencies:     []string{},
			Nonce:            strconv.Itoa(rand.Int()),
			BatcherPublicKey: cf.signer.GetPublicKey().AsHex(),
			Inputs:           inputs,
			Outputs:          outputs,
			PayloadSha512:    tpCrypto.SHA512HexFromBytes(seaStoragePayload.ToBytes()),
		}
		transactionHeader, err := proto.Marshal(&rawTransactionHeader)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize transaction header: %v", err)
		}

		// Signature of TransactionHeader
		transactionHeaderSignature := hex.EncodeToString(cf.signer.Sign(transactionHeader))

		// Construct Transaction
		transaction := &transaction_pb2.Transaction{
			Header:          transactionHeader,
			HeaderSignature: transactionHeaderSignature,
			Payload:         seaStoragePayload.ToBytes(),
		}

		transactions = append(transactions, transaction)
	}

	// Get BatchList
	rawBatchList, err := cf.createBatchList(transactions)
	if err != nil {
		return nil, fmt.Errorf("unable to construct batch list: %v", err)
	}
	batchID := rawBatchList.Batches[0].HeaderSignature
	batchList, err := proto.Marshal(&rawBatchList)
	if err != nil {
		return nil, fmt.Errorf("unable to serialize batch list: %v", err)
	}

	if wait > 0 {
		waitTime := uint(0)
		startTime := time.Now()
		response, err := sendRequestByAPISuffix(BatchSubmitAPI, batchList, ContentTypeOctetStream)
		if err != nil {
			return nil, err
		}
		for waitTime < wait {
			status, err := cf.getStatus(batchID, wait-waitTime)
			if err != nil {
				return nil, err
			}
			waitTime = uint(time.Now().Sub(startTime))
			if status["status"].(string) != "PENDING" {
				return response, nil
			}
		}
		return response, nil
	}

	return sendRequestByAPISuffix(BatchSubmitAPI, batchList, ContentTypeOctetStream)
}

// create the list of batches.
func (cf *ClientFramework) createBatchList(transactions []*transaction_pb2.Transaction) (batch_pb2.BatchList, error) {
	// Get list of TransactionHeader signatures
	var transactionSignatures []string
	for _, transaction := range transactions {
		transactionSignatures = append(transactionSignatures, transaction.HeaderSignature)
	}

	// Construct BatchHeader
	rawBatchHeader := batch_pb2.BatchHeader{
		SignerPublicKey: cf.signer.GetPublicKey().AsHex(),
		TransactionIds:  transactionSignatures,
	}
	batchHeader, err := proto.Marshal(&rawBatchHeader)
	if err != nil {
		return batch_pb2.BatchList{}, fmt.Errorf("unable to serialize batch header: %v", err)
	}

	// Signature of BatchHeader
	batchHeaderSignature := hex.EncodeToString(cf.signer.Sign(batchHeader))

	// Construct Batch
	batch := batch_pb2.Batch{
		Header:          batchHeader,
		Transactions:    transactions,
		HeaderSignature: batchHeaderSignature,
	}

	// Construct BatchList
	return batch_pb2.BatchList{
		Batches: []*batch_pb2.Batch{&batch},
	}, nil
}

// waiting for batch committed for register.
func (cf *ClientFramework) waitingForRegister(wait uint) bool {
	result := make(chan bool)
	defer close(result)
	go func() {
		ticker := time.NewTicker(time.Duration(1) * time.Second)
		i := uint(0)
		for i <= wait {
			select {
			case <-ticker.C:
				u, err := cf.GetData()
				if err == nil && u != nil {
					result <- true
					return
				}
				i++
			}
		}
		result <- false
	}()
	return <-result
}

// TODO: Subscribing events
//func (c *ClientFramework) subscribingToEvents(action string, id string) error {
//}

// GenerateKey generate key pair (Secp256k1) and store them in the storage path.
func GenerateKey(keyName string, keyPath string) {
	cont := signing.NewSecp256k1Context()
	pri := cont.NewRandomPrivateKey()
	pub := cont.GetPublicKey(pri)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		err = os.MkdirAll(keyPath, 0755)
		if err != nil {
			panic(err)
		}
	}
	err := ioutil.WriteFile(path.Join(keyPath, keyName+".priv"), []byte(pri.AsHex()), 0600)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(path.Join(keyPath, keyName+".pub"), []byte(pub.AsHex()), 0600)
	if err != nil {
		panic(err)
	}
}

// PrintResponse display the response in JSON.
func PrintResponse(response map[string]interface{}) {
	data, err := json.MarshalIndent(response, "", "\t")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))
}
