package lib

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/sawtooth-sdk-go/logging"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/batch_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/protobuf/transaction_pb2"
	"github.com/hyperledger/sawtooth-sdk-go/signing"
	"gitlab.com/SeaStorage/SeaStorage/crypto"
	"gitlab.com/SeaStorage/SeaStorage/payload"
	"gitlab.com/SeaStorage/SeaStorage/state"
	"gitlab.com/SeaStorage/SeaStorage/user"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var logger = logging.Get()

const (
	StatusPending   = "PENDING"
	StatusCommitted = "COMMITTED"
	StatusInvalid   = "INVALID"
)

type Client struct {
	Name     string
	Category string `user:"User" group:"Group" sea:"Sea"`
	url      string
	signer   *signing.Signer
}

func NewClient(name string, category string, url string, keyFile string) (Client, error) {
	if keyFile == "" {
		return Client{}, errors.New("need a valid key")
	}
	// Read private key file
	privateKeyHex, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return Client{}, errors.New(fmt.Sprintf("Failed to read private key: %v", err))
	}
	// Get private key object
	privateKey := signing.NewSecp256k1PrivateKey(crypto.HexToBytes(string(privateKeyHex)))
	cryptoFactory := signing.NewCryptoFactory(signing.NewSecp256k1Context())
	signer := cryptoFactory.NewSigner(privateKey)
	return Client{Name: name, Category: category, url: url, signer: signer}, nil
}

func (c Client) Register(name string) (map[interface{}]interface{}, error) {
	var seaStoragePayload payload.SeaStoragePayload
	switch c.Category {
	case "User":
		seaStoragePayload.Action = payload.CreateUser
		seaStoragePayload.Target = name
		c.Name = name
	case "Group":
		seaStoragePayload.Name = c.Name
		seaStoragePayload.Target = name
		seaStoragePayload.Action = payload.CreateGroup
	case "Sea":
		seaStoragePayload.Action = payload.CreateSea
		seaStoragePayload.Target = name
	default:
		return nil, errors.New("client category is invalid")
	}
	response, err := c.SendTransaction([]payload.SeaStoragePayload{seaStoragePayload}, 0)
	if err != nil {
		return nil, err
	}
	logger.Debug(response)
	if c.waitingForRegister(60) {
		return response, nil
	} else {
		return response, errors.New("waiting for register")
	}
}

func (c Client) List(start string, limit uint) (result []interface{}, err error) {
	apiSuffix := fmt.Sprintf("%s?address=%s", StateApi, c.getPrefix())
	if start != "" {
		apiSuffix = fmt.Sprintf("%s&start=%s", apiSuffix, start)
	}
	if limit > 0 {
		apiSuffix = fmt.Sprintf("%s&limit=%v", apiSuffix, limit)
	}
	response, err := c.sendRequestByAPISuffix(apiSuffix, []byte{}, "")
	if err != nil {
		return
	}
	return response["data"].([]interface{}), nil
}

func (c Client) Show() (*user.User, error) {
	apiSuffix := fmt.Sprintf("%s/%s", StateApi, c.getAddress())
	response, err := c.sendRequestByAPISuffix(apiSuffix, []byte{}, "")
	if err != nil {
		return nil, err
	}
	data, ok := response["data"]
	if !ok {
		return nil, errors.New("error reading as string")
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(data.(string))
	if err != nil {
		return nil, err
	}
	return user.UserFromBytes(decodedBytes)
}

func (c Client) getStatus(batchId string, wait uint) (map[interface{}]interface{}, error) {
	// API to call
	apiSuffix := fmt.Sprintf("%s?id=%s&wait=%d", BatchStatusApi, batchId, wait)
	response, err := c.sendRequestByAPISuffix(apiSuffix, []byte{}, "")
	if err != nil {
		return nil, err
	}

	entry := response["data"].([]interface{})[0].(map[interface{}]interface{})
	return entry, nil
}

func (c Client) sendRequestByAPISuffix(apiSuffix string, data []byte, contentType string) (map[interface{}]interface{}, error) {
	// Construct url
	var url string
	if strings.HasPrefix(c.url, "http://") {
		url = fmt.Sprintf("%s/%s", c.url, apiSuffix)
	} else {
		url = fmt.Sprintf("http://%s/%s", c.url, apiSuffix)
	}

	return c.sendRequest(url, data, contentType)
}

func (c Client) sendRequest(url string, data []byte, contentType string) (map[interface{}]interface{}, error) {
	// Send request to validator URL
	var response *http.Response
	var err error
	if len(data) > 0 {
		response, err = http.Post(url, contentType, bytes.NewBuffer(data))
	} else {
		response, err = http.Get(url)
	}
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to connect to REST API: %v", err))
	}
	if response.StatusCode == 404 {
		return nil, errors.New(fmt.Sprintf("No such endpoint: %s", url))
	} else if response.StatusCode >= 400 {
		return nil, errors.New(fmt.Sprintf("Error %d: %s", response.StatusCode, response.Status))
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error reading response: %v", err))
	}
	responseMap := make(map[interface{}]interface{})
	err = yaml.Unmarshal(responseBody, &responseMap)
	if err != nil {
		return nil, err
	}
	return responseMap, nil
}

func (c Client) SendTransaction(seaStoragePayloads []payload.SeaStoragePayload, wait uint) (map[interface{}]interface{}, error) {
	var transactions []*transaction_pb2.Transaction

	for _, seaStoragePayload := range seaStoragePayloads {
		// construct the address
		address := c.getAddress()

		// Construct TransactionHeader
		rawTransactionHeader := transaction_pb2.TransactionHeader{
			SignerPublicKey:  c.signer.GetPublicKey().AsHex(),
			FamilyName:       FamilyName,
			FamilyVersion:    FamilyVersion,
			Dependencies:     []string{},
			Nonce:            strconv.Itoa(rand.Int()),
			BatcherPublicKey: c.signer.GetPublicKey().AsHex(),
			Inputs:           []string{address},
			Outputs:          []string{address},
			PayloadSha512:    crypto.SHA512HexFromBytes(seaStoragePayload.ToBytes()),
		}
		transactionHeader, err := proto.Marshal(&rawTransactionHeader)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Unable to serialize transaction header: %v", err))
		}

		// Signature of TransactionHeader
		transactionHeaderSignature := hex.EncodeToString(c.signer.Sign(transactionHeader))

		// Construct Transaction
		transaction := &transaction_pb2.Transaction{
			Header:          transactionHeader,
			HeaderSignature: transactionHeaderSignature,
			Payload:         seaStoragePayload.ToBytes(),
		}

		transactions = append(transactions, transaction)
	}

	// Get BatchList
	rawBatchList, err := c.createBatchList(transactions)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to construct batch list: %v", err))
	}
	batchId := rawBatchList.Batches[0].HeaderSignature
	batchList, err := proto.Marshal(&rawBatchList)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to serialize batch list: %v", err))
	}

	if wait > 0 {
		waitTime := uint(0)
		startTime := time.Now()
		response, err := c.sendRequestByAPISuffix(BatchSubmitApi, batchList, ContentTypeOctetStream)
		if err != nil {
			return nil, err
		}
		for waitTime < wait {
			status, err := c.getStatus(batchId, wait-waitTime)
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

	return c.sendRequestByAPISuffix(BatchSubmitApi, batchList, ContentTypeOctetStream)
}

func (c Client) getPrefix() string {
	return state.Namespace
}

func (c Client) getAddress() string {
	switch c.Category {
	case "User":
		return state.MakeAddress(state.AddressTypeUser, c.Name, c.signer.GetPublicKey().AsHex())
	case "Group":
		return state.MakeAddress(state.AddressTypeGroup, c.Name, c.signer.GetPublicKey().AsHex())
	case "Sea":
		return state.MakeAddress(state.AddressTypeSea, c.Name, c.signer.GetPublicKey().AsHex())
	default:
		return ""
	}
}

func (c Client) createBatchList(transactions []*transaction_pb2.Transaction) (batch_pb2.BatchList, error) {
	// Get list of TransactionHeader signatures
	var transactionSignatures []string
	for _, transaction := range transactions {
		transactionSignatures = append(transactionSignatures, transaction.HeaderSignature)
	}

	// Construct BatchHeader
	rawBatchHeader := batch_pb2.BatchHeader{
		SignerPublicKey: c.signer.GetPublicKey().AsHex(),
		TransactionIds:  transactionSignatures,
	}
	batchHeader, err := proto.Marshal(&rawBatchHeader)
	if err != nil {
		return batch_pb2.BatchList{}, errors.New(fmt.Sprintf("Unable to serialize batch header: %v", err))
	}

	// Signature of BatchHeader
	batchHeaderSignature := hex.EncodeToString(c.signer.Sign(batchHeader))

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

func (c Client) waitingForRegister(wait uint) bool {
	result := make(chan bool)
	defer close(result)
	go func() {
		ticker := time.NewTicker(time.Duration(1) * time.Second)
		i := uint(0)
		for i <= wait {
			select {
			case <-ticker.C:
				u, err := c.Show()
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
//func (c Client) subscribingToEvents(action string, id string) error {
//}

func GenerateKey(keyName string, path string) {
	cont := signing.NewSecp256k1Context()
	pri := cont.NewRandomPrivateKey()
	pub := cont.GetPublicKey(pri)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(path, 0755)
		if err != nil {
			panic(err)
		}
	}
	err := ioutil.WriteFile(path+keyName+".priv", []byte(pri.AsHex()), 0600)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(path+keyName+".pub", []byte(pub.AsHex()), 0600)
	if err != nil {
		panic(err)
	}
}
