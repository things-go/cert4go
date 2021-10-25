package cert4go

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	privateKeyPKCS1Filename = "testdata/private_key.key"
	privateKeyPKCS8Filename = "testdata/private_key_pkcs8.pem"
	publicKeyPKCS1Filename  = "testdata/public_key.pub"
	// publicKeyPKCS8Filename  = "testdata/public_key_pkcs8.pem"
)

func TestRSAPCKS1(t *testing.T) {
	pri1, err := LoadRSAPKCS1PrivateKeyFromPEMFile(privateKeyPKCS1Filename)
	require.NoError(t, err)
	pri2, err := LoadRSAPrivateKeyFromPEMFile(privateKeyPKCS1Filename)
	require.NoError(t, err)
	pri3, err := LoadRSAPrivateKeyFromFile(privateKeyPKCS1Filename)
	require.NoError(t, err)

	_, err = LoadRSAPKCS8PrivateKeyFromPEMFile(privateKeyPKCS1Filename)
	require.Error(t, err)

	pub1, err := LoadRSAPublicKeyFromPEMFile(publicKeyPKCS1Filename)
	require.NoError(t, err)
	require.True(t, pri1.PublicKey.Equal(pub1))
	require.True(t, pri2.PublicKey.Equal(pub1))
	require.True(t, pri3.PublicKey.Equal(pub1))
	pub2, err := LoadRSAPublicKeyFromFile(publicKeyPKCS1Filename)
	require.NoError(t, err)
	require.True(t, pri1.PublicKey.Equal(pub2))
	require.True(t, pri2.PublicKey.Equal(pub2))
}

func TestRSAPCKS8(t *testing.T) {
	pri1, err := LoadRSAPKCS8PrivateKeyFromPEMFile(privateKeyPKCS8Filename)
	require.NoError(t, err)
	pri2, err := LoadRSAPrivateKeyFromPEMFile(privateKeyPKCS8Filename)
	require.NoError(t, err)
	pri3, err := LoadRSAPrivateKeyFromFile(privateKeyPKCS8Filename)
	require.NoError(t, err)

	_, err = LoadRSAPKCS1PrivateKeyFromPEMFile(privateKeyPKCS8Filename)
	require.Error(t, err)

	pub1, err := LoadRSAPublicKeyFromPEMFile(publicKeyPKCS1Filename)
	require.NoError(t, err)
	require.True(t, pri1.PublicKey.Equal(pub1))
	require.True(t, pri2.PublicKey.Equal(pub1))
	require.True(t, pri3.PublicKey.Equal(pub1))
	pub2, err := LoadRSAPublicKeyFromFile(publicKeyPKCS1Filename)
	require.NoError(t, err)
	require.True(t, pri1.PublicKey.Equal(pub2))
	require.True(t, pri2.PublicKey.Equal(pub2))
}
