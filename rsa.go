package cert4go

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/pkcs12"
)

var (
	ErrNotPEMEncodedKey = errors.New("cert4go: key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPrivateKey = errors.New("cert4go: key is not a valid RSA private key")
	ErrNotRSAPublicKey  = errors.New("cert4go: key is not a valid RSA public key")
	ErrNotCertificate   = errors.New("cert4go: key is not a valid certificate")
	ErrNotRSAPfxData    = errors.New("cert4go: pfx data not a valid data")
)

// ParseRSAPKCS1PrivateKeyFromPEM PEM encoded PKCS1 private key
// if password exist,PEM encoded PKCS1 private key protected with password,
// it will decode with password
func ParseRSAPKCS1PrivateKeyFromPEM(key []byte, password ...string) (*rsa.PrivateKey, error) {
	var err error
	var derBytes []byte

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	derBytes = block.Bytes
	if len(password) > 0 {
		derBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
		if err != nil {
			return nil, err
		}
	}
	return x509.ParsePKCS1PrivateKey(derBytes)
}

// ParseRSAPKCS8PrivateKeyFromPEM PEM encoded PKCS8 private key
// if password exist,PEM encoded PKCS8 private key protected with password,
// it will decode with password
func ParseRSAPKCS8PrivateKeyFromPEM(key []byte, password ...string) (*rsa.PrivateKey, error) {
	var err error
	var derBytes []byte

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	derBytes = block.Bytes
	if len(password) > 0 {
		derBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
		if err != nil {
			return nil, err
		}
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return nil, err
	}
	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	return pkey, nil
}

// ParseRSAPrivateKeyFromPEM PEM encoded PKCS1 or PKCS8 private key
// if password exist,PEM encoded PKCS1 or PKCS8 private key protected with password,
// it will decode with password
func ParseRSAPrivateKeyFromPEM(key []byte, password ...string) (*rsa.PrivateKey, error) {
	var err error
	var derBytes []byte

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	derBytes = block.Bytes
	if len(password) > 0 {
		derBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
		if err != nil {
			return nil, err
		}
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(derBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(derBytes); err != nil {
			return nil, err
		}
	}
	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	return pkey, nil
}

// ParseRSAPrivateKey parse public key
// - Pem format PKCS1 or PKCS8 public key
//   if password exist,PEM encoded PKCS1 or PKCS8 private key protected with password,
//   it will decode with password
// - PKIX, ASN.1 DER form public key
func ParseRSAPrivateKey(key []byte, password ...string) (*rsa.PrivateKey, error) {
	var err error

	derBytes := key
	block, _ := pem.Decode(key)
	if block != nil {
		derBytes = block.Bytes
		if len(password) > 0 {
			derBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
			if err != nil {
				return nil, err
			}
		}
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(derBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(derBytes); err != nil {
			return nil, err
		}
	}
	pkey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAPrivateKey
	}
	return pkey, nil
}

// ParseRSAPublicKeyFromPEM parse public key
// - Pem format PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte, password ...string) (*rsa.PublicKey, error) {
	var err error
	var derBytes []byte

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotPEMEncodedKey
	}

	derBytes = block.Bytes
	if len(password) > 0 {
		derBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
		if err != nil {
			return nil, err
		}
	}
	parsedKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		if cert, err := x509.ParseCertificate(derBytes); err != nil {
			if parsedKey, err = x509.ParsePKCS1PublicKey(derBytes); err != nil {
				return nil, err
			}
		} else {
			parsedKey = cert.PublicKey
		}
	}
	pkey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSAPublicKey
	}
	return pkey, nil
}

// ParseRSAPublicKey parse public key
// - Pem format PKCS1 or PKCS8 public key
// - PKIX, ASN.1 DER form public key
func ParseRSAPublicKey(key []byte, password ...string) (*rsa.PublicKey, error) {
	var err error
	var derBytes []byte

	block, _ := pem.Decode(key)
	if block != nil {
		derBytes = block.Bytes
		if len(password) > 0 {
			derBytes, err = x509.DecryptPEMBlock(block, []byte(password[0]))
			if err != nil {
				return nil, err
			}
		}
	}

	parsedKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		if cert, err := x509.ParseCertificate(derBytes); err != nil {
			if parsedKey, err = x509.ParsePKCS1PublicKey(derBytes); err != nil {
				return nil, err
			}
		} else {
			parsedKey = cert.PublicKey
		}
	}
	pkey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSAPublicKey
	}
	return pkey, nil
}

func ParseCertificateFromPEM(key []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, ErrNotCertificate
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParseCertificate(key []byte) (*x509.Certificate, error) {
	var derBytes []byte

	block, _ := pem.Decode(key)
	if block != nil {
		derBytes = block.Bytes
	}
	return x509.ParseCertificate(derBytes)
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
