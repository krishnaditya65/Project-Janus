package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/krishnaditya65/Project-Janus/internal/token/domain"
)

func GenerateKey(algorithm string) (*domain.SigningKey, error) {
	switch algorithm {
	case "ES256":
		return generateES256()
	case "RS256":
		return generateRS256()
	}
	return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
}

func generateES256() (*domain.SigningKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return &domain.SigningKey{
		ID:         uuid.NewString(),
		Algorithm:  "ES256",
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
		IsActive:   true,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func generateRS256() (*domain.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return &domain.SigningKey{
		ID:         uuid.NewString(),
		Algorithm:  "RS256",
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
		IsActive:   true,
		CreatedAt:  time.Now().UTC(),
	}, nil
}
