package cpt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

var (
	ErrNotPEMEncodedKey = errors.New("cert4go: key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPrivateKey = errors.New("cert4go: Key is not a valid RSA private key")
	ErrNotRSAPublicKey  = errors.New("cert4go: Key is not a valid RSA public key")
)

func LoadRSAPrivateKeyFromFile(name string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	key, err := ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func LoadRSAPublicKeyFromFile(name string) (*rsa.PublicKey, error) {
	keyData, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	key, err := ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Parse PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 private key protected with password
func ParseRSAPrivateKeyFromPEMWithPassword(key []byte, password string) (*rsa.PrivateKey, error) {
	// Parse PEM block
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	blockDecrypted, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return nil, err
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(blockDecrypted); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(blockDecrypted); err != nil {
			return nil, err
		}
	}

	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	pkey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSAPublicKey
	}
	return pkey, nil
}
