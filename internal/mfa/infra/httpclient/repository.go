// Package httpclient implements mfadomain.Repository (and a small client for
// mfa-service's Redis-backed challenge store) by calling mfa-service's
// internal HTTP API instead of touching Postgres/Redis directly. It mirrors
// internal/identity/infra/httpclient: the composition-root-injected
// dependency for auth's LoginUseCase, which used to be handed a
// Postgres-backed mfapostgres.Repository and a Redis-backed
// *mfaapp.ChallengeStore directly before mfa became its own service.
//
// Failure mode: any transport error, non-2xx status this client does not
// recognize, or response decode error is returned as an error. There is no
// fallback to local database/Redis access - callers must treat a failure
// here the same way they always have.
package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	mfadomain "github.com/krishnaditya65/Project-Janus/internal/mfa/domain"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

const defaultTimeout = 5 * time.Second

// Repository implements mfadomain.Repository by calling mfa-service at
// baseURL (e.g. "http://mfa-service:8082"). A trailing slash is tolerated.
type Repository struct {
	baseURL string
	client  *http.Client
}

func NewRepository(baseURL string) *Repository {
	return &Repository{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: defaultTimeout},
	}
}

func (r *Repository) Create(ctx context.Context, factor *mfadomain.Factor) error {
	body, err := json.Marshal(factor)
	if err != nil {
		return fmt.Errorf("mfa httpclient: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		r.baseURL+"/internal/mfa/factors",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("mfa httpclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("mfa httpclient: create: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		var created mfadomain.Factor
		if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
			return fmt.Errorf("mfa httpclient: decode response: %w", err)
		}
		*factor = created
		return nil
	default:
		return unexpectedStatus("create", resp)
	}
}

func (r *Repository) GetByID(ctx context.Context, id string) (*mfadomain.Factor, error) {
	endpoint := r.baseURL + "/internal/mfa/factors/" + url.PathEscape(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("mfa httpclient: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mfa httpclient: get: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var factor mfadomain.Factor
		if err := json.NewDecoder(resp.Body).Decode(&factor); err != nil {
			return nil, fmt.Errorf("mfa httpclient: decode response: %w", err)
		}
		return &factor, nil
	case http.StatusNotFound:
		return nil, sharederrors.ErrNotFound
	default:
		return nil, unexpectedStatus("get", resp)
	}
}

func (r *Repository) GetByIdentity(ctx context.Context, identityID string) ([]*mfadomain.Factor, error) {
	endpoint := r.baseURL + "/internal/mfa/factors/by-identity?identity_id=" + url.QueryEscape(identityID)
	return r.listFactors(ctx, endpoint)
}

func (r *Repository) GetVerifiedByIdentity(ctx context.Context, identityID string) ([]*mfadomain.Factor, error) {
	endpoint := r.baseURL + "/internal/mfa/factors/verified?identity_id=" + url.QueryEscape(identityID)
	return r.listFactors(ctx, endpoint)
}

func (r *Repository) listFactors(ctx context.Context, endpoint string) ([]*mfadomain.Factor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("mfa httpclient: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mfa httpclient: list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, unexpectedStatus("list", resp)
	}

	var factors []*mfadomain.Factor
	if err := json.NewDecoder(resp.Body).Decode(&factors); err != nil {
		return nil, fmt.Errorf("mfa httpclient: decode response: %w", err)
	}
	return factors, nil
}

func (r *Repository) MarkVerified(ctx context.Context, id string) error {
	endpoint := r.baseURL + "/internal/mfa/factors/" + url.PathEscape(id) + "/verify"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("mfa httpclient: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("mfa httpclient: mark verified: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	default:
		return unexpectedStatus("mark verified", resp)
	}
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	endpoint := r.baseURL + "/internal/mfa/factors/" + url.PathEscape(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("mfa httpclient: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("mfa httpclient: delete: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		// Not found is treated as success: the desired end state (no
		// factor with this ID) already holds - same convention as
		// identity's httpclient.Repository.Delete.
		return nil
	default:
		return unexpectedStatus("delete", resp)
	}
}

func unexpectedStatus(op string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("mfa httpclient: %s: unexpected status %d: %s", op, resp.StatusCode, string(b))
}
