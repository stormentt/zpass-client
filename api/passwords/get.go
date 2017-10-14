package passwords

import (
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"zpass-client/api"
	"zpass-client/keyvault"
	"zpass-lib/canister"
)

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
