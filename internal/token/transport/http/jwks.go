package http

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/krishnaditya65/Project-Janus/internal/token/domain"
)

type Handler struct {
	keyRepo domain.Repository
}

func NewHandler(keyRepo domain.Repository) *Handler {
	return &Handler{keyRepo: keyRepo}
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := h.keyRepo.ListPublic(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	response := jwksResponse{Keys: make([]jwk, 0, len(keys))}
	for _, k := range keys {
		j, err := toJWK(k)
		if err != nil {
			continue
		}
		response.Keys = append(response.Keys, j)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(response)
}

func toJWK(k *domain.SigningKey) (jwk, error) {
	block, _ := pem.Decode([]byte(k.PublicKey))
	if block == nil {
		return jwk{}, http.ErrBodyNotAllowed
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return jwk{}, err
	}

	switch k.Algorithm {
	case "ES256":
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return jwk{}, http.ErrBodyNotAllowed
		}
		return jwk{
			Kty: "EC",
			Use: "sig",
			Alg: "ES256",
			Kid: k.ID,
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(ec.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(ec.Y.Bytes()),
		}, nil
	case "RS256":
		rs, ok := pub.(*rsa.PublicKey)
		if !ok {
			return jwk{}, http.ErrBodyNotAllowed
		}
		return jwk{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: k.ID,
			N:   base64.RawURLEncoding.EncodeToString(rs.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigIntBytes(rs.E)),
		}, nil
	}
	return jwk{}, http.ErrBodyNotAllowed
}

func bigIntBytes(n int) []byte {
	b := make([]byte, 0, 4)
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	if len(b) == 0 {
		b = []byte{0}
	}
	return b
}
