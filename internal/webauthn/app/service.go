package app

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	"github.com/krishnaditya65/Project-Janus/internal/shared/id"
	"github.com/krishnaditya65/Project-Janus/internal/webauthn/domain"
)

var ErrUnknownCredential = errors.New("unknown credential")

type Service struct {
	webauthn     *wa.WebAuthn
	credRepo     domain.Repository
	identityRepo identitydomain.Repository
	sessions     *SessionStore
}

func NewService(rpDisplayName, rpID string, rpOrigins []string, credRepo domain.Repository, identityRepo identitydomain.Repository, sessions *SessionStore) (*Service, error) {
	w, err := wa.New(&wa.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &Service{
		webauthn:     w,
		credRepo:     credRepo,
		identityRepo: identityRepo,
		sessions:     sessions,
	}, nil
}

func (s *Service) BeginRegistration(ctx context.Context, identityID string) (*protocol.CredentialCreation, string, error) {
	identity, err := s.identityRepo.GetByID(ctx, identityID)
	if err != nil {
		return nil, "", err
	}

	existing, err := s.credRepo.ListByIdentity(ctx, identityID)
	if err != nil {
		return nil, "", err
	}

	userHandle := []byte(identityID)
	if len(existing) > 0 {
		userHandle = existing[0].UserHandle
	}

	user := &WAUser{
		ID:          userHandle,
		Name:        identity.PrimaryEmail,
		DisplayName: identity.PrimaryEmail,
		Creds:       existing,
	}

	options, sessionData, err := s.webauthn.BeginRegistration(user,
		wa.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		wa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, "", err
	}

	sessionKey := id.New()
	if err := s.sessions.Store(ctx, sessionKey, sessionData); err != nil {
		return nil, "", err
	}
	return options, sessionKey, nil
}

func (s *Service) FinishRegistration(ctx context.Context, identityID, sessionKey, label string, r *http.Request) (*domain.Credential, error) {
	sessionData, err := s.sessions.Consume(ctx, sessionKey)
	if err != nil {
		return nil, err
	}

	identity, err := s.identityRepo.GetByID(ctx, identityID)
	if err != nil {
		return nil, err
	}

	existing, _ := s.credRepo.ListByIdentity(ctx, identityID)
	userHandle := sessionData.UserID
	if len(existing) > 0 {
		userHandle = existing[0].UserHandle
	}

	user := &WAUser{
		ID:          userHandle,
		Name:        identity.PrimaryEmail,
		DisplayName: identity.PrimaryEmail,
		Creds:       existing,
	}

	cred, err := s.webauthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		return nil, err
	}

	stored := &domain.Credential{
		ID:           id.New(),
		IdentityID:   identityID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		Attestation:  cred.AttestationType,
		AAGUID:       cred.Authenticator.AAGUID,
		SignCount:    cred.Authenticator.SignCount,
		UserHandle:   userHandle,
		Label:        label,
		CreatedAt:    time.Now().UTC(),
	}
	for _, t := range cred.Transport {
		stored.Transports = append(stored.Transports, string(t))
	}
	if err := s.credRepo.Create(ctx, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

func (s *Service) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	options, sessionData, err := s.webauthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	sessionKey, err := randomKey()
	if err != nil {
		return nil, "", err
	}
	if err := s.sessions.Store(ctx, sessionKey, sessionData); err != nil {
		return nil, "", err
	}
	return options, sessionKey, nil
}

func (s *Service) FinishLogin(ctx context.Context, sessionKey string, r *http.Request) (*domain.Credential, error) {
	sessionData, err := s.sessions.Consume(ctx, sessionKey)
	if err != nil {
		return nil, err
	}

	handler := func(rawID, userHandle []byte) (wa.User, error) {
		creds, err := s.credRepo.ListByUserHandle(ctx, userHandle)
		if err != nil || len(creds) == 0 {
			return nil, ErrUnknownCredential
		}
		identity, err := s.identityRepo.GetByID(ctx, creds[0].IdentityID)
		if err != nil {
			return nil, err
		}
		return &WAUser{
			ID:          userHandle,
			Name:        identity.PrimaryEmail,
			DisplayName: identity.PrimaryEmail,
			Creds:       creds,
		}, nil
	}

	cred, err := s.webauthn.FinishDiscoverableLogin(handler, *sessionData, r)
	if err != nil {
		return nil, err
	}

	stored, err := s.credRepo.GetByCredentialID(ctx, cred.ID)
	if err != nil {
		return nil, err
	}
	_ = s.credRepo.UpdateSignCount(ctx, stored.ID, cred.Authenticator.SignCount)
	return stored, nil
}

func (s *Service) List(ctx context.Context, identityID string) ([]*domain.Credential, error) {
	return s.credRepo.ListByIdentity(ctx, identityID)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	return s.credRepo.Delete(ctx, id)
}

func randomKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return id.New(), nil
}
