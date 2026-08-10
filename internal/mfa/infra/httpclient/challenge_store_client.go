package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	mfaapp "github.com/krishnaditya65/Project-Janus/internal/mfa/app"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

// ChallengeStoreClient implements the same Store/Consume contract as
// *mfaapp.ChallengeStore (see internal/mfa/app/challenge_store.go), but
// backed by mfa-service's internal HTTP API instead of a direct Redis
// connection. It exists so auth's LoginUseCase (see internal/auth/app,
// which defines a minimal ChallengeStore interface satisfied by this type)
// needs no call-site changes beyond the field/constructor type.
type ChallengeStoreClient struct {
	baseURL string
	client  *http.Client
}

// NewChallengeStoreClient builds a ChallengeStoreClient that calls
// mfa-service at baseURL (e.g. "http://mfa-service:8082"). A trailing slash
// is tolerated.
func NewChallengeStoreClient(baseURL string) *ChallengeStoreClient {
	return &ChallengeStoreClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: defaultTimeout},
	}
}

func (c *ChallengeStoreClient) Store(ctx context.Context, challenge *mfaapp.Challenge) error {
	body, err := json.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("mfa httpclient: encode challenge: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/internal/mfa/challenges",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("mfa httpclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("mfa httpclient: store challenge: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusCreated:
		return nil
	default:
		return unexpectedStatus("store challenge", resp)
	}
}

func (c *ChallengeStoreClient) Consume(ctx context.Context, token string) (*mfaapp.Challenge, error) {
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return nil, fmt.Errorf("mfa httpclient: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/internal/mfa/challenges/consume",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("mfa httpclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mfa httpclient: consume challenge: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var challenge mfaapp.Challenge
		if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
			return nil, fmt.Errorf("mfa httpclient: decode response: %w", err)
		}
		return &challenge, nil
	case http.StatusNotFound:
		return nil, sharederrors.ErrNotFound
	default:
		return nil, unexpectedStatus("consume challenge", resp)
	}
}
