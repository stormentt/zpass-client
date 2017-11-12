package keyvault

import (
	"bytes"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-lib/canister"
	"github.com/stormentt/zpass-lib/crypt"
	"github.com/stormentt/zpass-lib/util"
)

var (
	encryptionKey     []byte
	AuthenticationKey []byte
	DeviceSelector    string
	VaultCrypter      crypt.Crypter
	kdfSalt           []byte
	vaultPath         string
	PassCrypter       crypt.Crypter
)

//Save saves whatever changes may have been made to the keyvault
func Save() error {
	return Write(vaultPath)
}

//Write writes out the current keyvault state to an encrypted file
func Write(path string) error {
	cLog := log.WithFields(log.Fields{
		"path": path,
	})

	cLog.Info("Writing KeyVault")
	keyCan := canister.New()
	keyCan.
		Set("encryptionKey", encryptionKey).
		Set("authenticationKey", AuthenticationKey).
		Set("deviceSelector", DeviceSelector)
	keyCanJson, err := keyCan.ToJSON()
	if err != nil {
		return err
	}

	encryptedKeyCan, err := VaultCrypter.Encrypt([]byte(keyCanJson))
	if err != nil {
		return err
	}

	vaultCan := canister.New()
	vaultCan.
		Set("kdfSalt", kdfSalt).
		Set("keyVault", encryptedKeyCan)

	vault, err := os.Create(path)
	if err != nil {
		return err
	}

	err = vaultCan.Release(vault)
	if err != nil {
		return err
	}

	return nil
}

//Create creates a new keyvault & generates encryption keys
func Create(path string) error {
	cLog := log.WithFields(log.Fields{
		"path": path,
	})
	cLog.Info("Creating keyvault")
	vaultPath = path
	tmpCrypter, _ := crypt.NewCrypter(nil, nil)
	tmpHasher, _ := crypt.NewHasher(nil, nil)
	encryptionKey, _ = tmpCrypter.GenKey()
	AuthenticationKey, _ = tmpHasher.GenKey()

	var password []byte
	match := false
	for match == false {
		password1, _ := util.AskPass("Enter new KeyVault Encryption Key: ")

		password2, _ := util.AskPass("Repeat new KeyVault Encryption Key: ")

		match = bytes.Equal(password1, password2)
		password = password1
	}

	VaultCrypter, _ = crypt.NewCrypter(nil, nil)
	salt, err := VaultCrypter.DeriveKey(password)
	if err != nil {
		return err
	}

	kdfSalt = salt

	PassCrypter, _ = crypt.NewCrypter(encryptionKey, nil)

	return Write(path)
}

func Open(path string) error {
	vaultPath = path
	VaultCrypter, _ = crypt.NewCrypter(nil, nil)
	cLog := log.WithFields(log.Fields{
		"path": path,
	})
	cLog.Info("Opening keyvault")

	vaultCan, err := canister.FillFrom(path)
	if err != nil {
		return err
	}

	kdfSalt, err = vaultCan.GetBytes("kdfSalt")
	if err != nil {
		return err
	}

	encryptedKeyCan, err := vaultCan.GetBytes("keyVault")
	if err != nil {
		return err
	}

	password, _ := util.AskPass("Enter KeyVault Encryption Key: ")

	err = VaultCrypter.CalcKey(password, kdfSalt)
	if err != nil {
		return err
	}

	keyCanJson, err := VaultCrypter.Decrypt(encryptedKeyCan)
	if err != nil {
		return err
	}

	keyCan, err := canister.Fill(string(keyCanJson))
	if err != nil {
		return err
	}

	AuthenticationKey, _ = keyCan.GetBytes("authenticationKey")
	encryptionKey, _ = keyCan.GetBytes("encryptionKey")
	DeviceSelector, _ = keyCan.GetString("deviceSelector")

	PassCrypter, _ = crypt.NewCrypter(encryptionKey, nil)

	return nil
}
