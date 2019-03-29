package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"

	"github.com/tiendung1510/rsautil"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Generate key pair
	pri, pub, err := rsautil.GenerateKeyPair(512)
	check(err)

	// Convert public key to bytes
	pubBytes, err := rsautil.PublicKeyToBytes(pub)
	check(err)

	// Convert private key to bytes
	priBytes, err := rsautil.PrivateKeyToBytes(pri)
	check(err)

	log.Println(string(pubBytes))
	log.Println(string(priBytes))

	// Convert bytes to public key
	pub2, err := rsautil.BytesToPublicKey(pubBytes)
	check(err)

	// Encrypt message with publickey
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub2, []byte("github.com/tiendung1510/rsautil"))
	check(err)

	log.Println(string(ciphertext))

	// Convert bytes to private key
	pri2, err := rsautil.BytesToPrivateKey(priBytes)
	check(err)

	// Descrypt ciphertext with private key
	message, err := rsa.DecryptPKCS1v15(rand.Reader, pri2, ciphertext)
	check(err)

	log.Println(string(message))
}
