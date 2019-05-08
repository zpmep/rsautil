package rsautil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

/*
	This source code is referenced from: https://gist.github.com/miguelmota/3ea9286bd1d3c2a985b67cac4ba2130a
*/

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) ([]byte, error) {
	priASN1, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: priASN1,
		},
	), nil
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	}), nil
}

// BytesToPublicKey convert from bytes to public key
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, fmt.Errorf("There is no PEM data in this key")
	}
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		//log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("This key is not a rsa public key")
	}
	return key, nil
}

// BytesToPrivateKey convert from bytes to private key
func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, fmt.Errorf("There is no PEM data in this key")
	}
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("This key is not a rsa private key")
	}
	return key, nil
}

// Encrypt given text with given *rsa.PublicKey
func Encrypt(pub *rsa.PublicKey, text string) (string, error) {
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(text))
	return string(cipherText), err
}

func EncryptToBase64(pub *rsa.PublicKey, text string) (string, error) {
	cipherText, err := Encrypt(pub, text)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(cipherText)), nil
}

// Decrypt given ciptherText with given *rsa.PrivateKey
func Decrypt(priv *rsa.PrivateKey, cipherText string) (string, error) {
	text, err := rsa.DecryptPKCS1v15(rand.Reader, priv, []byte(cipherText))
	return string(text), err
}
