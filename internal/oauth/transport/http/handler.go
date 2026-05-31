package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	oauthapp "github.com/krishnaditya65/Project-Janus/internal/oauth/app"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

type Handler struct {
	authorizeUseCase *oauthapp.AuthorizeUseCase
	tokenUseCase     *oauthapp.TokenUseCase
}

func NewHandler(authorizeUseCase *oauthapp.AuthorizeUseCase, tokenUseCase *oauthapp.TokenUseCase) *Handler {
	return &Handler{authorizeUseCase: authorizeUseCase, tokenUseCase: tokenUseCase}
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	q := r.URL.Query()
	out, err := h.authorizeUseCase.Execute(r.Context(), oauthapp.AuthorizeInput{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
		Principal:           p,
	})
	if err != nil {
		oauthErrorRedirect(w, r, q.Get("redirect_uri"), q.Get("state"), err)
		return
	}

	u, err := url.Parse(out.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	rq := u.Query()
	rq.Set("code", out.Code)
	if out.State != "" {
		rq.Set("state", out.State)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "malformed form", http.StatusBadRequest)
		return
	}

	clientID, clientSecret := extractClientCreds(r)

	in := oauthapp.TokenInput{
		GrantType:    r.PostForm.Get("grant_type"),
		Code:         r.PostForm.Get("code"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		CodeVerifier: r.PostForm.Get("code_verifier"),
		RefreshToken: r.PostForm.Get("refresh_token"),
		Scope:        r.PostForm.Get("scope"),
	}

	out, err := h.tokenUseCase.Execute(r.Context(), in)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, oauthapp.ErrInvalidClient):
			status = http.StatusUnauthorized
			writeOAuthError(w, "invalid_client", err.Error(), status)
		case errors.Is(err, oauthapp.ErrInvalidGrant):
			writeOAuthError(w, "invalid_grant", err.Error(), status)
		case errors.Is(err, oauthapp.ErrUnsupportedGrant):
			writeOAuthError(w, "unsupported_grant_type", err.Error(), status)
		default:
			writeOAuthError(w, "server_error", "internal error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(out)
}

func extractClientCreds(r *http.Request) (string, string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}

type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func writeOAuthError(w http.ResponseWriter, code, desc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(oauthError{Error: code, ErrorDescription: desc})
}

func oauthErrorRedirect(w http.ResponseWriter, r *http.Request, redirectURI, state string, err error) {
	if redirectURI == "" {
		writeOAuthError(w, mapErrorCode(err), err.Error(), http.StatusBadRequest)
		return
	}
	u, parseErr := url.Parse(redirectURI)
	if parseErr != nil {
		writeOAuthError(w, "invalid_request", "bad redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", mapErrorCode(err))
	q.Set("error_description", fmt.Sprint(err))
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func mapErrorCode(err error) string {
	switch {
	case errors.Is(err, oauthapp.ErrInvalidClient):
		return "invalid_client"
	case errors.Is(err, oauthapp.ErrInvalidRedirectURI):
		return "invalid_request"
	case errors.Is(err, oauthapp.ErrUnsupportedResponse):
		return "unsupported_response_type"
	case errors.Is(err, oauthapp.ErrInvalidScope):
		return "invalid_scope"
	case errors.Is(err, oauthapp.ErrMissingPKCE), errors.Is(err, oauthapp.ErrUnsupportedChallenge):
		return "invalid_request"
	case errors.Is(err, oauthapp.ErrUnsupportedGrant):
		return "unsupported_grant_type"
	}
	return "server_error"
}
