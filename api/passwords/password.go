package passwords

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io/ioutil"
	"zpass-client/api"
	"zpass-client/keyvault"
)

func Store() {
	log.Info("storing password")
	err := keyvault.Open(viper.GetString("keyvault-path"))
	if err != nil {
		log.Error(err)
		return
	}
	req := api.NewRequest()
	req.
		Dest("passwords", "POST").
		Set("yolo", "test")
	response, err := req.Send()
	if err != nil {
		log.Error(err)
		return
	}

	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	fmt.Println(string(body))
}
