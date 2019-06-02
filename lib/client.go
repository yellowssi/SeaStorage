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
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/sawtooth-sdk-go/messaging"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/batch_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/client_event_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/events_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/transaction_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/validator_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/signing"
	"github.com/pebbe/zmq4"
	"github.com/sirupsen/logrus"
	tpCrypto "github.com/yellowssi/SeaStorage-TP/crypto"
	tpPayload "github.com/yellowssi/SeaStorage-TP/payload"
	tpState "github.com/yellowssi/SeaStorage-TP/state"
	tpUser "github.com/yellowssi/SeaStorage-TP/user"
)

// The Category of ClientFramework.
const (
	ClientCategoryUser = true
	ClientCategorySea  = false
)

// ClientFramework provides SeaStorage base operations for both user and sea.
type ClientFramework struct {
	Name     string // The name of user or sea.
	Category bool   // The category of client framework.
	signer   *signing.Signer
	zmqConn  *messaging.ZmqConnection
	done     chan error
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
	cf := &ClientFramework{
		Name:     name,
		Category: category,
		signer:   signer,
		done:     make(chan error),
	}
	err = cf.generateZmqConnection()
	return cf, err
}

// Close is the deconstruct for ClientFramework.
func (cf *ClientFramework) Close() {
	close(cf.done)
	cf.zmqConn.Close()
}

// Register user or sea. Create user or sea in the blockchain.
func (cf *ClientFramework) Register(name string) error {
	var seaStoragePayload tpPayload.SeaStoragePayload
	if cf.Category {
		seaStoragePayload.Action = tpPayload.CreateUser
	} else {
		seaStoragePayload.Action = tpPayload.CreateSea
	}
	seaStoragePayload.Target = []string{name}
	cf.Name = name
	return cf.SendTransactionAndWaiting([]tpPayload.SeaStoragePayload{seaStoragePayload}, []string{cf.GetAddress()}, []string{cf.GetAddress()})
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
func (cf *ClientFramework) getStatus(batchID string, wait int64) (map[string]interface{}, error) {
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
func (cf *ClientFramework) SendTransaction(seaStoragePayloads []tpPayload.SeaStoragePayload, inputs, outputs []string) (string, error) {
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
			return "", fmt.Errorf("unable to serialize transaction header: %v", err)
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
		return "", fmt.Errorf("unable to construct batch list: %v", err)
	}
	batchList, err := proto.Marshal(&rawBatchList)
	if err != nil {
		return "", fmt.Errorf("unable to serialize batch list: %v", err)
	}

	response, err := sendRequestByAPISuffix(BatchSubmitAPI, batchList, ContentTypeOctetStream)
	if err != nil {
		return "", err
	}
	return strings.Split(response["link"].(string), "id=")[1], nil
}

// SendTransactionAndWaiting send transaction by the batch and waiting for the batches committed.
func (cf *ClientFramework) SendTransactionAndWaiting(seaStoragePayloads []tpPayload.SeaStoragePayload, inputs, outputs []string) error {
	batchID, err := cf.SendTransaction(seaStoragePayloads, inputs, outputs)
	if err != nil {
		return err
	}
	return cf.WaitingForCommitted(batchID)
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

// WaitingForCommitted wait for batches committed.
// If timeout or batches invalid, it will return error.
func (cf *ClientFramework) WaitingForCommitted(blockID string) error {
	subscription := &events_pb2.EventSubscription{
		EventType: "sawtooth/block-commit",
		Filters: []*events_pb2.EventFilter{{
			Key:        blockID,
			FilterType: events_pb2.EventFilter_SIMPLE_ANY,
		}},
	}
	go func() {
		err := cf.subscribeEvents([]*events_pb2.EventSubscription{subscription})
		if err != nil {
			cf.done <- err
		}
	}()
	select {
	case err := <-cf.done:
		return err
	case <-time.After(DefaultWait):
		return errors.New("waiting for committed timeout")
	}
}

func (cf *ClientFramework) subscribeEvents(subscriptions []*events_pb2.EventSubscription) error {
	// Construct the subscribeRequest
	subscribeRequest := &client_event_pb2.ClientEventsSubscribeRequest{
		Subscriptions: subscriptions,
	}
	requestBytes, err := proto.Marshal(subscribeRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal subscription subscribeRequest: %v", err)
	}
	corrID, err := cf.zmqConn.SendNewMsg(validator_pb2.Message_CLIENT_EVENTS_SUBSCRIBE_REQUEST, requestBytes)
	if err != nil {
		return fmt.Errorf("failed to send subscription message: %v", err)
	}
	// Received subscription response
	_, response, err := cf.zmqConn.RecvMsgWithId(corrID)
	if err != nil {
		return fmt.Errorf("failed to received subscribe event response: %v", err)
	}
	subscribeResponse := &client_event_pb2.ClientEventsSubscribeResponse{}
	err = proto.Unmarshal(response.Content, subscribeResponse)
	if err != nil {
		return fmt.Errorf("failed to unmarshal subscribe response: %v", err)
	}
	if subscribeResponse.Status != client_event_pb2.ClientEventsSubscribeResponse_OK {
		return errors.New("failed to subscribe event")
	}
	defer func(correlationID string) {
		err := cf.unsubscribeEvents(correlationID)
		if err != nil {
			Logger.WithFields(logrus.Fields{
				"correlationID": correlationID,
			}).Error(err)
		}
	}(corrID)
	cf.subscribeHandler()
	return nil
}

func (cf *ClientFramework) unsubscribeEvents(corrID string) error {
	// Construct the UnsubscribeRequest
	unsubscribeRequest := &client_event_pb2.ClientEventsUnsubscribeRequest{}
	unsubscribeRequestBytes, err := proto.Marshal(unsubscribeRequest)
	if err != nil {
		Logger.WithFields(logrus.Fields{
			"correlationID": corrID,
		}).Errorf("failed to unsubscribe event: %v", err)
	}
	id, err := cf.zmqConn.SendNewMsg(validator_pb2.Message_CLIENT_EVENTS_UNSUBSCRIBE_REQUEST, unsubscribeRequestBytes)
	if err != nil {
		return fmt.Errorf("faield to send unsubscribe event message: %v", err)
	}
	// Received the unsubscription response
	_, response, err := cf.zmqConn.RecvMsgWithId(id)
	if err != nil {
		return fmt.Errorf("failed to received unsubcribe event response: %v", err)
	}
	unsubscribeResponse := &client_event_pb2.ClientEventsUnsubscribeResponse{}
	err = proto.Unmarshal(response.Content, unsubscribeResponse)
	if err != nil {
		return fmt.Errorf("failed to unmarshal unsubscribe event response: %v", err)
	}
	if unsubscribeResponse.Status != client_event_pb2.ClientEventsUnsubscribeResponse_OK {
		return errors.New("failed to unsubscribe event")
	}
	return nil
}

func (cf *ClientFramework) subscribeHandler() {
	for {
		_, message, err := cf.zmqConn.RecvMsg()
		if err != nil {
			Logger.Errorf("zmq failed to received message: %v", err)
			continue
		}
		if message.MessageType != validator_pb2.Message_CLIENT_EVENTS {
			continue
		}
		eventList := &events_pb2.EventList{}
		err = proto.Unmarshal(message.Content, eventList)
		if err != nil {
			Logger.WithFields(logrus.Fields{
				"message": message.String(),
			}).Error("failed unmarshal message")
			continue
		}
		Logger.Info(message.String())
		Logger.Info(eventList.String())
		cf.done <- nil
		break
	}
}

func (cf *ClientFramework) generateZmqConnection() error {
	// Setup a connection to the validator
	ctx, err := zmq4.NewContext()
	if err != nil {
		return err
	}
	zmqConn, err := messaging.NewConnection(ctx, zmq4.DEALER, ValidatorURL, false)
	if err != nil {
		return err
	}
	cf.zmqConn = zmqConn
	return nil
}

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
