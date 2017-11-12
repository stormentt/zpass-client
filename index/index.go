package index

import (
	"errors"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-client/keyvault"
	"github.com/stormentt/zpass-lib/canister"
)

var (
	index *canister.Canister
)

func New(path string) error {
	index = canister.New()
	return Save(path)
}

//Add adds the name & selector to the index
func Add(name, selector string) error {
	if index.Has(name) {
		err := errors.New("Password already exists.")
		log.Error(err)
		return err
	}

	index.Set(name, selector)
	return nil
}

// Get retrieves the selector with the given name from the index
func Get(name string) (string, bool) {
	return index.GetString(name)
}

//List returns the json encoded version of the index
func List() string {
	json, _ := index.ToJSON()
	return json
}

//Open reads the index from the given path
func Open(path string) error {
	f, err := os.Open(path)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Unable to open index")
		return err
	}
	defer f.Close()

	encryptedIndex, err := ioutil.ReadAll(f)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Unable to read index")
		return err
	}

	indexJson, err := keyvault.VaultCrypter.Decrypt(encryptedIndex)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Unable to decrypt index")
		return err
	}

	index, err = canister.Fill(string(indexJson))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Unable to decode index json")
		return err
	}

	return nil
}

// Save saves the index at the given path
func Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Unable to create index")
		return err
	}
	defer f.Close()

	json, _ := index.ToJSON()
	encryptedJson, err := keyvault.VaultCrypter.Encrypt([]byte(json))
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Unable to encrypt index")
		return err
	}

	_, err = f.Write(encryptedJson)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Error("Unable to write index")
		return err
	}

	return nil
}
