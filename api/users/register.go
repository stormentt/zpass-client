package users

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io/ioutil"
	"zpass-client/api"
	"zpass-client/keyvault"
)

func Register() {
	log.Info("Registering")
	keyvault.Initialize(viper.GetString("keyvault-path"))
	req := api.NewRequest()
	req.
		Dest("users", "POST").
		Set("deviceName", "device").
		SetBytes("deviceAuthKey", keyvault.AuthenticationKey)
	response, err := req.Send()
	if err != nil {
		//TODO: better error handling
		return
	}

	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode != 201 {
		log.WithFields(log.Fields{
			"code":    response.StatusCode,
			"headers": response.Header,
			"body":    body,
		}).Error("Received non-success code")
		return
	}

	fmt.Println(string(body))
}
