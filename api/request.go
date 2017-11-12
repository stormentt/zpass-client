package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stormentt/zpass-client/keyvault"
	"github.com/stormentt/zpass-lib/crypt"
	"github.com/stormentt/zpass-lib/nonces"
	"github.com/stormentt/zpass-lib/util"
)

//Request is a struct representing a request to the API
type Request struct {
	//Map is the actual request information
	Map map[string]interface{}
	//Payload is what we're going to send the endpoint
	Payload string
	//MAC is the HMAC digest of Payload
	MAC string
	//Destination is the path to send to
	Destination string
	//Method is what http method to use
	Method string
}

// NewRequest returns a blank api request
func NewRequest() *Request {
	var request Request
	request.Map = make(map[string]interface{})
	return &request
}

// Dest sets the destination endpoint & the method for the request
func (r *Request) Dest(dest, method string) *Request {
	r.Destination = dest
	r.Method = method
	return r
}

// Set stores the given value in the payload map
func (r *Request) Set(property string, value interface{}) *Request {
	r.Map[property] = value
	return r
}

// SetBytes does the same thing as Set, but it encodes the value to base64 first
func (r *Request) SetBytes(property string, value []byte) *Request {
	b64 := util.EncodeB64(value)
	r.Map[property] = b64
	return r
}

// JSON encodes the request's payload map
func (r *Request) Json() *Request {
	json, _ := util.EncodeJson(r.Map)
	r.Payload = json
	return r
}

// Compact compacts the payload string to form a smaller payload
func (r *Request) Compact() *Request {
	var b bytes.Buffer
	json.Compact(&b, []byte(r.Payload))
	r.Payload = b.String()
	return r
}

// CompactJSON calls both Json and Compact
func (r *Request) CompactJson() *Request {
	return r.Json().Compact()
}

//HMAC calculates the HMAC digest of the payload string
func (r *Request) HMAC() *Request {
	hasher, _ := crypt.NewHasher(keyvault.AuthenticationKey, nil)
	hmac := hasher.Digest([]byte(r.Payload))
	hmacB64 := util.EncodeB64(hmac)

	log.WithFields(log.Fields{
		"r":    r,
		"hmac": hmacB64,
	}).Debug("Calculating HMAC")

	r.MAC = hmacB64
	return r
}

//Nonce creates a nonce & stores it in the payload map
func (r *Request) Nonce() *Request {
	nonce, _ := nonces.Make()
	r.Set("nonce", nonce)
	return r
}

//Send connects to the server & sends the payload string, returning an http.Response on success
func (r *Request) Send() (*http.Response, error) {
	r.Nonce().CompactJson().HMAC()

	baseUrl := "http://" + viper.GetString("server") + ":" + strconv.Itoa(viper.GetInt("port")) + "/"
	url := baseUrl + r.Destination
	req, _ := http.NewRequest(r.Method, url, bytes.NewBuffer([]byte(r.Payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-HMAC", r.MAC)
	req.Header.Set("Device-Selector", keyvault.DeviceSelector)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.WithFields(log.Fields{
			"url":     url,
			"method":  r.Method,
			"payload": r.Payload,
			"error":   err,
		}).Error("Error sending request")
		return nil, err
	}

	return resp, nil
}
