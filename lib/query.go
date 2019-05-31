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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	tpSea "gitlab.com/SeaStorage/SeaStorage-TP/sea"
	tpState "gitlab.com/SeaStorage/SeaStorage-TP/state"
)

// GetStateData returns the data of the address in byte slice.
func GetStateData(addr string) ([]byte, error) {
	apiSuffix := fmt.Sprintf("%s/%s", StateAPI, addr)
	resp, err := sendRequestByAPISuffix(apiSuffix, nil, "")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp["data"].(string))
}

// List returns the list of data that address started with the address prefix.
func list(address, start string, limit uint) (result []interface{}, err error) {
	apiSuffix := fmt.Sprintf("%s?address=%s", StateAPI, address)
	if start != "" {
		apiSuffix = fmt.Sprintf("%s&start=%s", apiSuffix, start)
	}
	if limit > 0 {
		apiSuffix = fmt.Sprintf("%s&limit=%v", apiSuffix, limit)
	}
	response, err := sendRequestByAPISuffix(apiSuffix, nil, "")
	if err != nil {
		return
	}
	return response["data"].([]interface{}), nil
}

// ListAll returns the list of data that address started with the SeaStorage's namespace.
func ListAll(start string, limit uint) ([]interface{}, error) {
	return list(tpState.Namespace, start, limit)
}

// ListUsers returns the list of data that address started with the UserNamespace.
func ListUsers(start string, limit uint) ([]interface{}, error) {
	return list(tpState.Namespace+tpState.UserNamespace, start, limit)
}

// ListSeas returns the list of data that address started with the SeaNamespace.
func ListSeas(start string, limit uint) ([]interface{}, error) {
	return list(tpState.Namespace+tpState.SeaNamespace, start, limit)
}

// ListSeasPublicKey returns the list of sea's public key.
func ListSeasPublicKey(start string, limit uint) ([]string, error) {
	seas, err := ListSeas(start, limit)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for i := range seas {
		seaBytes, err := base64.StdEncoding.DecodeString(seas[i].(map[string]interface{})["data"].(string))
		if err != nil {
			continue
		}
		s, err := tpSea.SeaFromBytes(seaBytes)
		if err != nil {
			continue
		}
		result = append(result, s.PublicKey)
	}
	return result, nil
}

// sendRequest send the request to the Hyperledger Sawtooth rest api by giving url.
func sendRequest(url string, data []byte, contentType string) (map[string]interface{}, error) {
	// SendUploadQuery request to validator URL
	var response *http.Response
	var err error
	if len(data) > 0 {
		response, err = http.Post(url, contentType, bytes.NewBuffer(data))
	} else {
		response, err = http.Get(url)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to REST API: %v", err)
	}
	if response.StatusCode == 404 {
		return nil, fmt.Errorf("no such endpoint: %s", url)
	} else if response.StatusCode >= 400 {
		return nil, fmt.Errorf("error %d: %s", response.StatusCode, response.Status)
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}
	responseMap := make(map[string]interface{})
	err = json.Unmarshal(responseBody, &responseMap)
	if err != nil {
		return nil, err
	}
	return responseMap, nil
}

// sendRequest send the request to the Hyperledger Sawtooth rest api by giving api suffix.
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
