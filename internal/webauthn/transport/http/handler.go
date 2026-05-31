package http

import (
	"encoding/json"
	"net/http"

	waapp "github.com/krishnaditya65/Project-Janus/internal/webauthn/app"

	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

type Handler struct {
	service        *waapp.Service
	loginUseCase   *waapp.LoginUseCase
	sessionKeyName string
}

func NewHandler(service *waapp.Service, loginUseCase *waapp.LoginUseCase) *Handler {
	return &Handler{service: service, loginUseCase: loginUseCase, sessionKeyName: "X-WebAuthn-Session"}
}

type registerBeginResp struct {
	SessionKey string `json:"session_key"`
	Options    any    `json:"options"`
}

func (h *Handler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	options, sessionKey, err := h.service.BeginRegistration(r.Context(), p.IdentityID)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, registerBeginResp{SessionKey: sessionKey, Options: options})
}

type registerCompleteReq struct {
	SessionKey string          `json:"session_key"`
	Label      string          `json:"label"`
	Response   json.RawMessage `json:"response"`
}

func (h *Handler) RegisterComplete(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req registerCompleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	innerReq := requestWithBody(r, req.Response)
	cred, err := h.service.FinishRegistration(r.Context(), p.IdentityID, req.SessionKey, req.Label, innerReq)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":    cred.ID,
		"label": cred.Label,
	})
}

type loginBeginResp struct {
	SessionKey string `json:"session_key"`
	Options    any    `json:"options"`
}

func (h *Handler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionKey, err := h.service.BeginLogin(r.Context())
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, loginBeginResp{SessionKey: sessionKey, Options: options})
}

type loginCompleteReq struct {
	SessionKey string          `json:"session_key"`
	Response   json.RawMessage `json:"response"`
}

func (h *Handler) LoginComplete(w http.ResponseWriter, r *http.Request) {
	var req loginCompleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	innerReq := requestWithBody(r, req.Response)
	result, err := h.loginUseCase.Complete(r.Context(), req.SessionKey, innerReq)
	if err != nil {
		writeError(w, err.Error(), http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	creds, err := h.service.List(r.Context(), p.IdentityID)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type out struct {
		ID         string   `json:"id"`
		Label      string   `json:"label"`
		Transports []string `json:"transports"`
		CreatedAt  string   `json:"created_at"`
		LastUsedAt *string  `json:"last_used_at"`
	}
	resp := make([]out, 0, len(creds))
	for _, c := range creds {
		o := out{ID: c.ID, Label: c.Label, Transports: c.Transports, CreatedAt: c.CreatedAt.Format("2006-01-02T15:04:05Z")}
		if c.LastUsedAt != nil {
			s := c.LastUsedAt.Format("2006-01-02T15:04:05Z")
			o.LastUsedAt = &s
		}
		resp = append(resp, o)
	}
	writeJSON(w, http.StatusOK, resp)
}
