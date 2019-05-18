package lib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	peer "github.com/libp2p/go-libp2p-peer"
	"gitlab.com/SeaStorage/SeaStorage-TP/crypto"
	"io/ioutil"
	"net/http"
	"strings"

	tpSea "gitlab.com/SeaStorage/SeaStorage-TP/sea"
	tpState "gitlab.com/SeaStorage/SeaStorage-TP/state"
)

func list(address, start string, limit uint) (result []interface{}, err error) {
	apiSuffix := fmt.Sprintf("%s?address=%s", StateApi, address)
	if start != "" {
		apiSuffix = fmt.Sprintf("%s&start=%s", apiSuffix, start)
	}
	if limit > 0 {
		apiSuffix = fmt.Sprintf("%s&limit=%v", apiSuffix, limit)
	}
	response, err := sendRequestByAPISuffix(apiSuffix, []byte{}, "")
	if err != nil {
		return
	}
	return response["data"].([]interface{}), nil
}

func ListAll(start string, limit uint) ([]interface{}, error) {
	return list(tpState.Namespace, start, limit)
}

func ListUsers(start string, limit uint) ([]interface{}, error) {
	return list(tpState.Namespace+tpState.UserNamespace, start, limit)
}

func ListSeas(start string, limit uint) ([]interface{}, error) {
	return list(tpState.Namespace+tpState.SeaNamespace, start, limit)
}

func ListSeasPeerId(start string, limit uint) ([]peer.ID, error) {
	seas, err := ListSeas(start, limit)
	if err != nil {
		return nil, err
	}
	result := make([]peer.ID, 0)
	for _, s := range seas {
		id, err := peer.IDFromString(crypto.SHA256HexFromHex(s.(*tpSea.Sea).PublicKey))
		if err != nil {
			continue
		}
		result = append(result, id)
	}
	return result, nil
}

func sendRequest(url string, data []byte, contentType string) (map[string]interface{}, error) {
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
	responseMap := make(map[string]interface{})
	err = json.Unmarshal(responseBody, &responseMap)
	if err != nil {
		return nil, err
	}
	return responseMap, nil
}

func sendRequestByAPISuffix(apiSuffix string, data []byte, contentType string) (map[string]interface{}, error) {
	var url string
	// Construct url
	if strings.HasPrefix(TPURL, "http://") {
		url = fmt.Sprintf("%s/%s", TPURL, apiSuffix)
	} else {
		url = fmt.Sprintf("http://%s/%s", TPURL, apiSuffix)
	}

	return sendRequest(url, data, contentType)
}
