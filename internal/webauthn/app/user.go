package app

import (
	wa "github.com/go-webauthn/webauthn/webauthn"

	"github.com/krishnaditya65/Project-Janus/internal/webauthn/domain"
)

type WAUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Creds       []*domain.Credential
}

func (u *WAUser) WebAuthnID() []byte          { return u.ID }
func (u *WAUser) WebAuthnName() string        { return u.Name }
func (u *WAUser) WebAuthnDisplayName() string { return u.DisplayName }

func (u *WAUser) WebAuthnCredentials() []wa.Credential {
	out := make([]wa.Credential, 0, len(u.Creds))
	for _, c := range u.Creds {
		out = append(out, wa.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.Attestation,
			Authenticator: wa.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}
	return out
}
