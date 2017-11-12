# zpass-client

Zpass is a self-hosted remote password manager.

## Why Zpass?

You 100% shouldn't use it right now, but here are its design goals & implementation plans:

* Passwords are encrypted in the client before being sent to the storage server.
* One user can (and should) have multiple devices registered with the storage server. Each device will be able to access your passwords.
* Fine-grained password permissions: Mark passwords as requiring 2 or more devices to authenticate before the server will release the password. Limit some devices to not being able to access certain passwords no matter what.
  * This is intended to stop a current issue with password managers: With traditional password managers, all of the passwords are stored encrypted on the client machine.
If that machine is compromised then so is every single password you have. With zpass, the only passwords that will be compromised are the ones you've used your other devices to release.
  * You could set your bank passwords to be only accessible by your personal computer, but it requires authentication from both your phone & your tablet & your personal computer.
* Zpass will eventually support encrypted file storage, with the same two-factor options as passwords
  * Possible planned feature: The zpass-client will have the option of using an in-memory file system for storing decrypted files. These files will be exposed via a WebDAV/NFS/other network sharing protocol.
The idea is that you can download your files, decrypt them in memory, mount the memory filesystem as a network share, edit them with your programs of choice, and then close out of the zpass-client to reencrypt & reupload your files.
    * There's definitely some security considerations with this (OS might swap the decrypted files in RAM, how to secure the network share, etc) so this feature may or may not happen. I don't want to give the illusion that the decrypted-in-ram files are impossible to get to.
  * Sharing files with other users
* Anonymous passwords: Store passwords without any devices/users associated with them. Anybody could retrieve the password but since its decrypted before you upload it, your passwords are still safe.
  * Anonymous files will also be supported
  * Combine this with a proxy & a storage server used by multiple people and you can have plausible deniability or whatever
* Multiple different choices for crypto backends. Right now Zpass only supports ChaCha20-Poly1305 for encrypting passwords. It'll support at least AES256 as well.
* Teams for password sharing
* SSL, don't worry. I don't have it yet because this is nowhere near production ready.

## Concepts
### Users & Devices
Every "person" is a user. Every user has multiple devices. Devices are used to authenticate to the zpass server. Each device has an authentication key that is used for this purpose.

### Authentication
Every request to the [zpass-server](https://github.com/stormentt/zpass-server) must be authenticated.
Requests are authenticated using SHA512-HMAC with the device authentication key as the symmetric key.

### Encryption vs. Device keys
Every user has an encryption key that is used solely for encrypting/decrypting passwords & files. This is distinct from the device keys, which a user will have multiple of. Device keys are used solely to authenticate each device to the zpass-server.

### Keyvault
The keyvault is an encrypted storage object used to keep your device keys & encryption keys secure. It is encrypted with a separate master password that you enter every time you use the client.

## Installing
```
go get -u github.com/stormentt/zpass-client
```

## Usage
Create a file ~/zpass-client.yaml with an example config:
```
keyvault-path: keyvault.json
index-path: index-file
server: localhost
port: 8080
```
You can also create the zpass-client.yaml file wherever your zpass-client binary is.
Eventually it'll get moved to a better config spot, this is still just a development version.

### Registering a device/user
```
zpass-client register
```
Zpass will ask you for a password to encrypt your keyvault with. After that it will generate an encryption key & a device key, and then save them into the keyvault. You can now add, retrieve, and update passwords.

### Adding a password
```
zpass-client add password
```
Zpass will ask you for your keyvault password and then prompt you to enter in a new password. 
It will also ask you to specify a password name, which you can later use to retrieve the password.

### Generating a password
```
zpass-client add password -g -l [length]
```
This will generate a random alphanumeric password [length] characters long. If you don't specify length, it'll generate a 32 character password.

### Retrieving a password
```
zpass-client get password -n [password name] -s [password selector]
```
This will attempt to retrieve your password from the storage server & print it to STDOUT.

You can provide either a name or a selector

### Updating a password
```
zpass-client update password [selector]
```
This will ask you for a new password and then overwrite the previous password on the storage server.

## Testing
There are no real tests yet but it's in the works.
[Zpass-lib](https://github.com/stormentt/zpass-lib) has tests though.

## Code Signing
Every code commit I make is signed by 6C7EF80BC4A6AD93. 

## Libraries used

* [Cobra](https://github.com/spf13/cobra)
* [Viper](https://github.com/spf13/viper)
* [Logrus](https://github.com/sirupsen/logrus)
* [Homedir](https://github.com/mitchellh/go-homedir)
* [zpass-lib](https://github.com/stormentt/zpass-lib)

## Contributing

I'll review pull requests & potentially integrate them. I'll have a contribution guide eventually.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/stormentt/zpass-client/tags).

## Authors

* Tanner Storment - Everything so far

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md](LICENSE.md) file for details
