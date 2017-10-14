package users

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io/ioutil"
	"github.com/stormentt/zpass-client/api"
	"github.com/stormentt/zpass-client/keyvault"
	"github.com/stormentt/zpass-lib/canister"
)

func Register() {
	log.Info("Registering")
	err := keyvault.Create(viper.GetString("keyvault-path"))
	if err != nil {
		log.Error(err)
		return
	}
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
			"body":    string(body),
		}).Error("Received non-success code")
		return
	}

	can, err := canister.Fill(string(body))
	if err != nil {
		log.WithFields(log.Fields{
			"body":  string(body),
			"error": err,
		}).Error("Unable to decode json")
		return
	}

	//TODO: Nonce & HMAC validation
	deviceSelector, _ := can.GetString("deviceSelector")
	keyvault.DeviceSelector = deviceSelector
	keyvault.Save()
	fmt.Println(string(body))
	fmt.Println(deviceSelector)
}
