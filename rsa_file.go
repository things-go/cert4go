package cert4go

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
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
	return ParseRSAPublicKey(keyData)
}

func LoadRSAPublicKeyFromPemFile(name string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPublicKeyFromPEM(keyData)
}

func LoadPfxFromFile(name, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, nil, err
	}
	return ParsePfx(keyData, password)
}
