package passwords

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-client/api"
	"github.com/stormentt/zpass-client/keyvault"
	"github.com/stormentt/zpass-lib/canister"
	"io/ioutil"
	"net/http"
)

// Store saves the given password to the server
func AnonStore(password string) (string, error) {
	log.Info("storing anon password")

	encrypted, _ := keyvault.PassCrypter.Encrypt([]byte(password))
	req := api.NewRequest()
	req.
		Dest("passwords", "POST").
		Set("password", encrypted)
	response, err := req.Send()
	if err != nil {
		log.Error(err)
		return "", err
	}

	if response.StatusCode != http.StatusCreated {
		return "", errors.New("Password not created")
	}

	body, _ := ioutil.ReadAll(response.Body)
	log.Info(string(body))
	can, _ := canister.Fill(string(body))
	selector, ok := can.GetString("anon-password.selector")
	if ok == false {
		return "", errors.New("No selector in response")
	}
	return selector, nil
}
