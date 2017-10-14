package passwords

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"net/http"
	"zpass-client/api"
	"zpass-client/keyvault"
)

func Store(password string) error {
	log.Info("storing password")

	encrypted, _ := keyvault.PassCrypter.Encrypt([]byte(password))
	req := api.NewRequest()
	req.
		Dest("passwords", "POST").
		Set("password", encrypted)
	response, err := req.Send()
	if err != nil {
		log.Error(err)
		return err
	}

	if response.StatusCode != http.StatusCreated {
		return errors.New("Password not created")
	}

	return nil
}
