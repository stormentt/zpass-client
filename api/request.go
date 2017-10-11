package api

import (
	"bytes"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"net/http"
	"strconv"
	"zpass-client/keyvault"
	"zpass-lib/crypt"
	"zpass-lib/nonces"
	"zpass-lib/util"
)

type Request struct {
	StatusCode  int
	Map         map[string]interface{}
	Payload     string
	MAC         string
	Destination string
	Method      string
}

func NewRequest() *Request {
	var request Request
	request.Map = make(map[string]interface{})
	return &request
}

func (r *Request) Dest(dest, method string) *Request {
	r.Destination = dest
	r.Method = method
	return r
}

func (r *Request) Set(property string, value interface{}) *Request {
	r.Map[property] = value
	return r
}

func (r *Request) SetBytes(property string, value []byte) *Request {
	b64 := util.EncodeB64(value)
	r.Map[property] = b64
	return r
}

func (r *Request) Json() *Request {
	json, _ := util.EncodeJson(r.Map)
	r.Payload = json
	return r
}

func (r *Request) Compact() *Request {
	var b bytes.Buffer
	json.Compact(&b, []byte(r.Payload))
	r.Payload = b.String()
	return r
}

func (r *Request) CompactJson() *Request {
	return r.Json().Compact()
}

func (r *Request) HMAC() *Request {
	hasher := crypt.NewHasher(keyvault.AuthenticationKey, nil)
	hmac := hasher.Digest([]byte(r.Payload))
	hmacB64 := util.EncodeB64(hmac)

	log.WithFields(log.Fields{
		"r":    r,
		"hmac": hmacB64,
	}).Debug("Calculating HMAC")

	r.MAC = hmacB64
	return r
}

func (r *Request) Nonce() *Request {
	nonce, _ := nonces.Make()
	r.Set("nonce", nonce)
	return r
}

func (r *Request) Send() (*http.Response, error) {
	r.Nonce().CompactJson().HMAC()

	baseUrl := "http://" + viper.GetString("server") + ":" + strconv.Itoa(viper.GetInt("port")) + "/"
	url := baseUrl + r.Destination
	req, _ := http.NewRequest(r.Method, url, bytes.NewBuffer([]byte(r.Payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-HMAC", r.MAC)

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
