package cert4go

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
)

func LoadRSAPKCS1PrivateKeyFromPEMFile(name string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPKCS1PrivateKeyFromPEM(keyData)
}

func LoadRSAPKCS8PrivateKeyFromPEMFile(name string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPKCS8PrivateKeyFromPEM(keyData)
}

func LoadRSAPrivateKeyFromPEMFile(name string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKeyFromPEM(keyData)
}

func LoadRSAPrivateKeyFromFile(name string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKey(keyData)
}

func LoadRSAPublicKeyFromPEMFile(name string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPublicKeyFromPEM(keyData)
}

func LoadRSAPublicKeyFromFile(name string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ParseRSAPublicKey(keyData)
}

func LoadPfxFromFile(name, password string) (*rsa.PrivateKey, *x509.Certificate, error) {
	keyData, err := os.ReadFile(name)
	if err != nil {
		return nil, nil, err
	}
	return ParsePfx(keyData, password)
}
