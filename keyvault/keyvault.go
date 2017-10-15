package keyvault

import (
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-lib/canister"
	"github.com/stormentt/zpass-lib/crypt"
	"github.com/stormentt/zpass-lib/util"
	"os"
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
	keyCanJson, err := keyCan.ToJson()
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
	tmpCrypter := crypt.NewCrypter(nil, nil)
	tmpHasher := crypt.NewHasher(nil, nil)
	encryptionKey, _ = tmpCrypter.GenKey()
	AuthenticationKey, _ = tmpHasher.GenKey()

	var password string
	match := false
	for match == false {
		password1, _ := util.AskPass("Enter new KeyVault Encryption Key: ")

		password2, _ := util.AskPass("Repeat new KeyVault Encryption Key: ")

		match = (string(password1) == string(password2))
		password = string(password1)
	}

	VaultCrypter = crypt.NewCrypter(nil, nil)
	wrapKey, salt, err := VaultCrypter.DeriveKey(password)
	if err != nil {
		return err
	}

	VaultCrypter.SetKeys(wrapKey, nil)
	kdfSalt = salt

	PassCrypter = crypt.NewCrypter(encryptionKey, nil)

	return Write(path)
}

func Open(path string) error {
	vaultPath = path
	VaultCrypter = crypt.NewCrypter(nil, nil)
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

	input, _ := util.AskPass("Enter KeyVault Encryption Key: ")
	password := string(input)

	wrapKey, err := VaultCrypter.CalcKey(password, kdfSalt)
	if err != nil {
		return err
	}

	VaultCrypter.SetKeys(wrapKey, nil)

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

	PassCrypter = crypt.NewCrypter(encryptionKey, nil)

	return nil
}
