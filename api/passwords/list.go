package passwords

import (
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-client/api"
	"io/ioutil"
	"net/http"
)

func List() string {
	log.Info("getting password list")
	req := api.NewRequest()
	req.Dest("passwords", "GET")
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
	//can, err := canister.Fill(string(body))
	if err != nil {
		return ""
	}
	//decrypted, _ := keyvault.PassCrypter.Decrypt(pass)
	return string(body)
}
