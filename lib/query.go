package lib

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
