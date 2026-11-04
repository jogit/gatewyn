// Package secrets chiffre les identifiants enregistrés en base (AES-256-GCM). La
// clé est un fichier créé au premier usage, à côté de la base : elle protège une
// copie de la base seule, pas un accès à tout le volume.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
)

// Box chiffre et déchiffre avec une clé.
type Box struct{ aead cipher.AEAD }

// Open lit la clé du fichier path, ou la crée (droits 0600) si elle n'existe pas.
func Open(path string) (*Box, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		err = os.WriteFile(path, key, 0o600)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("clé de chiffrement invalide : " + path)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead}, nil
}

// Seal chiffre text et renvoie une chaîne base64.
func (b *Box) Seal(text string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(text), nil)), nil
}

// Unseal déchiffre le résultat de Seal.
func (b *Box) Unseal(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", errors.New("donnée chiffrée illisible")
	}
	n := b.aead.NonceSize()
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("déchiffrement impossible (la clé a-t-elle changé ?)")
	}
	return string(plain), nil
}
