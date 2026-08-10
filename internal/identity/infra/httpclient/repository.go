// Package httpclient implements identitydomain.Repository by calling
// identity-service's internal HTTP API instead of touching Postgres
// directly. It is the composition-root-injected dependency for every
// bounded context that used to be handed a Postgres-backed
// identitypostgres.Repository (auth, mfa, oauth, webauthn, oidc) - their
// app-layer code is unchanged, since they only ever depended on the
// identitydomain.Repository interface.
//
// Failure mode: any transport error, non-2xx status this client does not
// recognize, or response decode error is returned as an error. There is no
// fallback to local database access - callers must treat a Repository
// failure the same way they always have (identity unavailable), not as
// "identity absent".
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

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

const defaultTimeout = 5 * time.Second

type Repository struct {
	baseURL string
	client  *http.Client
}

// NewRepository builds a Repository that calls identity-service at baseURL
// (e.g. "http://identity-service:8081"). A trailing slash is tolerated.
func NewRepository(baseURL string) *Repository {
	return &Repository{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: defaultTimeout},
	}
}

func (r *Repository) Create(
	ctx context.Context,
	identity *identitydomain.Identity,
) error {

	body, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("identity httpclient: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		r.baseURL+"/internal/identities",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("identity httpclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("identity httpclient: create: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		var created identitydomain.Identity
		if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
			return fmt.Errorf("identity httpclient: decode response: %w", err)
		}
		*identity = created
		return nil
	case http.StatusConflict:
		return sharederrors.ErrConflict
	default:
		return unexpectedStatus("create", resp)
	}
}

func (r *Repository) GetByEmail(
	ctx context.Context,
	email string,
) (*identitydomain.Identity, error) {

	endpoint := r.baseURL + "/internal/identities/by-email?email=" + url.QueryEscape(email)
	return r.get(ctx, endpoint)
}

func (r *Repository) GetByID(
	ctx context.Context,
	id string,
) (*identitydomain.Identity, error) {

	endpoint := r.baseURL + "/internal/identities/" + url.PathEscape(id)
	return r.get(ctx, endpoint)
}

func (r *Repository) Delete(
	ctx context.Context,
	id string,
) error {

	endpoint := r.baseURL + "/internal/identities/" + url.PathEscape(id)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("identity httpclient: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("identity httpclient: delete: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		// Not found is treated as success: the desired end state (no
		// identity with this ID) already holds.
		return nil
	default:
		return unexpectedStatus("delete", resp)
	}
}

func (r *Repository) get(
	ctx context.Context,
	endpoint string,
) (*identitydomain.Identity, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("identity httpclient: build request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("identity httpclient: get: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var identity identitydomain.Identity
		if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
			return nil, fmt.Errorf("identity httpclient: decode response: %w", err)
		}
		return &identity, nil
	case http.StatusNotFound:
		return nil, sharederrors.ErrNotFound
	default:
		return nil, unexpectedStatus("get", resp)
	}
}

func unexpectedStatus(op string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("identity httpclient: %s: unexpected status %d: %s", op, resp.StatusCode, string(b))
}
