package keyvault

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
	"os"
	"zpass-lib/canister"
	"zpass-lib/crypt"
)

var (
	EncryptionKey     []byte
	AuthenticationKey []byte
	DeviceSelector    string
	vaultCrypter      crypt.Crypter
	kdfSalt           []byte
	vaultPath         string
)

func Save() error {
	return Write(vaultPath)
}
func Write(path string) error {
	cLog := log.WithFields(log.Fields{
		"path": path,
	})

	cLog.Info("Writing KeyVault")
	keyCan := canister.New()
	keyCan.
		Set("encryptionKey", EncryptionKey).
		Set("authenticationKey", AuthenticationKey).
		Set("deviceSelector", DeviceSelector)
	keyCanJson, err := keyCan.ToJson()
	if err != nil {
		return err
	}

	encryptedKeyCan, err := vaultCrypter.Encrypt([]byte(keyCanJson))
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

	_, err = vaultCan.Release(vault)
	if err != nil {
		return err
	}

	return nil
}

func Create(path string) error {
	cLog := log.WithFields(log.Fields{
		"path": path,
	})
	cLog.Info("Creating keyvault")
	vaultPath = path
	tmpCrypter := crypt.NewCrypter(nil, nil)
	tmpHasher := crypt.NewHasher(nil, nil)
	EncryptionKey, _ = tmpCrypter.GenKey()
	AuthenticationKey, _ = tmpHasher.GenKey()

	var password string
	match := false
	for match == false {
		fmt.Println("Enter new KeyVault Encryption Key: ")
		password1, _ := terminal.ReadPassword(0)

		fmt.Println("Confirm new KeyVault Encryption Key: ")
		password2, _ := terminal.ReadPassword(0)

		match = (string(password1) == string(password2))
		password = string(password1)
	}

	vaultCrypter = crypt.NewCrypter(nil, nil)
	wrapKey, salt, err := vaultCrypter.DeriveKey(password)
	if err != nil {
		return err
	}

	vaultCrypter.SetKeys(wrapKey, nil)
	kdfSalt = salt

	return Write(path)
}

func Open(path string) error {
	vaultPath = path
	vaultCrypter = crypt.NewCrypter(nil, nil)
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

	input, _ := terminal.ReadPassword(0)
	password := string(input)

	wrapKey, err := vaultCrypter.CalcKey(password, kdfSalt)
	if err != nil {
		return err
	}

	vaultCrypter.SetKeys(wrapKey, nil)

	keyCanJson, err := vaultCrypter.Decrypt(encryptedKeyCan)
	if err != nil {
		return err
	}

	keyCan, err := canister.Fill(string(keyCanJson))
	if err != nil {
		return err
	}

	AuthenticationKey, _ = keyCan.GetBytes("authenticationKey")
	EncryptionKey, _ = keyCan.GetBytes("encryptionKey")
	DeviceSelector, _ = keyCan.GetString("deviceSelector")
	log.Error(DeviceSelector)

	return nil
}
