package keyvault

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"zpass-lib/crypt"
	"zpass-lib/util"
)

type KeyPair struct {
	EncryptionKey     string
	AuthenticationKey string
}

type KeyVault struct {
	//TODO: Implement NRP params in zpass-lib/util/crypt
	//N                int
	//R                int
	//P                int
	KDFSalt          string `json:"kdf-salt"`
	EncryptedKeyPair string `json:"encrypted-key-pair"`
}

var (
	EncryptionKey     []byte
	AuthenticationKey []byte
)

func checkErr(err error) {
	log.Fatal(err)
}

func Initialize(path string, authKey []byte) {
	cLog := log.WithFields(log.Fields{
		"path": path,
	})

	cLog.Info("Initializing KeyVault")
	crypter := crypt.NewCrypter(nil, nil)
	encryptKey := crypter.GenKey()
	var keys KeyPair
	keys.EncryptionKey = util.EncodeB64(encryptKey)
	keys.AuthenticationKey = util.EncodeB64(authKey)

	keypairJson, err := util.EncodeJson(keys)
	checkErr(err)

	var password string
	match := false
	for match == false {
		fmt.Println("Enter new KeyVault Encryption Key: ")
		password1, err := terminal.ReadPassword(0)
		checkErr(err)

		fmt.Println("Confirm new KeyVault Encryption Key: ")
		password2, err := terminal.ReadPassword(0)
		checkErr(err)

		match = (string(password1) == string(password2))
		password = string(password1)
	}

	wrapKey, salt, err := crypter.DeriveKey(password)
	checkErr(err)
	saltB64 := util.EncodeB64(salt)

	crypter.SetKeys(wrapKey, nil)

	var keyVault KeyVault
	keyVault.KDFSalt = saltB64

	encryptedKeyPair, err := crypter.Encrypt([]byte(keypairJson))
	checkErr(err)

	keyVault.EncryptedKeyPair = util.EncodeB64(encryptedKeyPair)
}

func Open(path string) {
	cLog := log.WithFields(log.Fields{
		"path": path,
	})

	cLog.Info("Opening KeyVault")
	vault, err := os.Open(path)
	checkErr(err)
	defer vault.Close()

	cLog.Info("Reading KeyVault")
	vaultBody, err := ioutil.ReadAll(vault)
	checkErr(err)

	cLog.Info("Decoding KeyVault to JSON")
	var keyVault KeyVault
	err = util.DecodeJson(string(vaultBody), &keyVault)
	checkErr(err)

	cLog.Info("Decoding base64 values")
	encrypted, err := util.DecodeB64(keyVault.EncryptedKeyPair)
	checkErr(err)

	kdfsalt, err := util.DecodeB64(keyVault.KDFSalt)
	checkErr(err)

	fmt.Println("Enter KeyVault password: ")
	password, err := terminal.ReadPassword(0)
	checkErr(err)

	crypter := crypt.NewCrypter(nil, nil)
	cLog.Info("Deriving Key")
	key, err := crypter.CalcKey(string(password), kdfsalt)
	checkErr(err)
	crypter.SetKeys(key, nil)

	cLog.Info("Decrypting KeyPair")
	decrypted, err := crypter.Decrypt(encrypted)
	checkErr(err)

	var Keys KeyPair
	err = util.DecodeJson(string(decrypted), &Keys)
	checkErr(err)

	EncryptionKey, err = util.DecodeB64(Keys.EncryptionKey)
	checkErr(err)
	AuthenticationKey, err = util.DecodeB64(Keys.AuthenticationKey)
	checkErr(err)

	cLog.Info("Opened Vault")
}
