package cpt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"golang.org/x/crypto/pkcs12"
)

var (
	ErrNotPEMEncodedKey = errors.New("cert4go: key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPrivateKey = errors.New("cert4go: Key is not a valid RSA private key")
	ErrNotRSAPublicKey  = errors.New("cert4go: Key is not a valid RSA public key")
	ErrNotRSAPfxData    = errors.New("cert4go: pfx data not a valid data")
)

func LoadRSAPrivateKeyFromFile(name string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKeyFromPEM(keyData)
}

func LoadRSAPublicKeyFromFile(name string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	key, err := ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func LoadPfxFromFile(name, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, nil, err
	}
	return ParsePfx(keyData, password)
}

// ParseRSAPrivateKeyFromPEM PEM encoded PKCS1 or PKCS8 private key
// if password exist,PEM encoded PKCS1 or PKCS8 private key protected with password,
// it will decode with password
func ParseRSAPrivateKeyFromPEM(key []byte, password ...string) (*rsa.PrivateKey, error) {
	var err error
	var blockBytes []byte

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	blockBytes = block.Bytes
	if len(password) > 0 {
		blockBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
		if err != nil {
			return nil, err
		}
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(blockBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(blockBytes); err != nil {
			return nil, err
		}
	}

	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	return pkey, nil
}

// ParseRSAPublicKeyFromPEM PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		parsedKey = cert.PublicKey
	}
	pkey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSAPublicKey
	}
	return pkey, nil
}

// ParseRSAPKCS1PrivateKeyFromPEM PEM encoded PKCS1 private key
// if password exist,PEM encoded PKCS1 private key protected with password,
// it will decode with password
func ParseRSAPKCS1PrivateKeyFromPEM(key []byte, password ...string) (*rsa.PrivateKey, error) {
	var err error
	var blockBytes []byte

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	blockBytes = block.Bytes
	if len(password) > 0 {
		blockBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
		if err != nil {
			return nil, err
		}
	}

	return x509.ParsePKCS1PrivateKey(blockBytes)
}

// ParseRSAPKCS8PrivateKeyFromPEM PEM encoded PKCS8 private key
// if password exist,PEM encoded PKCS8 private key protected with password,
// it will decode with password
func ParseRSAPKCS8PrivateKeyFromPEM(key []byte, password ...string) (*rsa.PrivateKey, error) {
	var err error
	var blockBytes []byte

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	blockBytes = block.Bytes
	if len(password) > 0 {
		blockBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
		if err != nil {
			return nil, err
		}
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(blockBytes)
	if err != nil {
		return nil, err
	}
	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	return pkey, nil
}

func ParsePfx(pfxData []byte, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	pkey, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return nil, nil, err
	}

	private, ok := pkey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, ErrNotRSAPfxData
	}
	return private, cert, nil
}
