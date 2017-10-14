package passwords

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"zpass-client/api"
	"zpass-client/keyvault"
	"zpass-lib/canister"
)

func Store(password string) {
	log.Info("storing password")

	encrypted, _ := keyvault.PassCrypter.Encrypt([]byte(password))
	req := api.NewRequest()
	req.
		Dest("passwords", "POST").
		Set("password", encrypted)
	response, err := req.Send()
	if err != nil {
		log.Error(err)
		return
	}

	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	fmt.Println(string(body))
}

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

	fmt.Println(response.StatusCode)
	if response.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := ioutil.ReadAll(response.Body)
	can, err := canister.Fill(string(body))
	if err != nil {
		return ""
	}
	fmt.Println(string(body))
	pass, _ := can.GetBytes("password.Data.Bytes")
	decrypted, _ := keyvault.PassCrypter.Decrypt(pass)
	fmt.Println(string(decrypted))
	return ""
}
