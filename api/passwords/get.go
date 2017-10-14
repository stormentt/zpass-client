package passwords

import (
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-client/api"
	"github.com/stormentt/zpass-client/keyvault"
	"github.com/stormentt/zpass-lib/canister"
	"io/ioutil"
	"net/http"
)

// Get returns the decrypted form of the requested password.
// If there is an error or the password is empty, it'll return an empty string.
func Get(selector string) string {
	log.Info("getting password")
	req := api.NewRequest()
	req.Dest("passwords/"+selector, "GET")
	response, err := req.Send()
	if err != nil {
		log.Error(err)
		return ""
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := ioutil.ReadAll(response.Body)
	can, err := canister.Fill(string(body))
	if err != nil {
		return ""
	}
	pass, err := can.GetBytes("password.data.bytes")
	if err != nil {
		log.Error(err)
		return ""
	}
	decrypted, _ := keyvault.PassCrypter.Decrypt(pass)
	return string(decrypted)
}
