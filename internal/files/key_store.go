package files

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	privateKeyFile = "private_key.pem"
	publicKeyFile  = "public_key.pem"
)

// GenerateKeyPair generates a new RSA key pair and saves it to the specified directory.
func GenerateKeyPair(dir string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	err = ioutil.WriteFile(filepath.Join(dir, privateKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0600)
	if err != nil {
		return err
	}

	pub := &priv.PublicKey
	pubBytes := x509.MarshalPKCS1PublicKey(pub)
	err = ioutil.WriteFile(filepath.Join(dir, publicKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), 0644)
	if err != nil {
		return err
	}

	return nil
}

// LoadPrivateKey loads the private key from the specified directory.
func LoadPrivateKey(dir string) (*rsa.PrivateKey, error) {
	privKeyPath := filepath.Join(dir, privateKeyFile)
	privKeyPEM, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// LoadPublicKey loads the public key from the specified directory.
func LoadPublicKey(dir string) (*rsa.PublicKey, error) {
	pubKeyPath := filepath.Join(dir, publicKeyFile)
	pubKeyPEM, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// Encrypt encrypts the given plaintext using the public key.
func Encrypt(plainText []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext using the private key.
func Decrypt(ciphertext []byte, privKey *rsa.PrivateKey) ([]byte, error) {
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// FileExists checks if the given file exists.
func FileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}
