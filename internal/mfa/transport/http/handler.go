package http

import (
	"encoding/json"
	"errors"
	"net/http"

	mfaapp "github.com/krishnaditya65/Project-Janus/internal/mfa/app"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

type Handler struct {
	totpService     *mfaapp.TOTPService
	completeUseCase *mfaapp.CompleteUseCase
}

func NewHandler(totpService *mfaapp.TOTPService, completeUseCase *mfaapp.CompleteUseCase) *Handler {
	return &Handler{totpService: totpService, completeUseCase: completeUseCase}
}

type enrollRequest struct {
	Label string `json:"label"`
}

func (h *Handler) EnrollTOTP(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req enrollRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	result, err := h.totpService.Enroll(r.Context(), p.IdentityID, p.Email, req.Label)
	if err != nil {
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

type verifyRequest struct {
	FactorID string `json:"factor_id"`
	Code     string `json:"code"`
}

func (h *Handler) VerifyEnrollment(w http.ResponseWriter, r *http.Request) {
	if _, ok := authctx.Principal(r.Context()); !ok {
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := h.totpService.VerifyEnrollment(r.Context(), req.FactorID, req.Code); err != nil {
		if errors.Is(err, mfaapp.ErrInvalidCode) {
			writeJSONError(w, "invalid code", http.StatusUnauthorized)
			return
		}
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type completeRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

func (h *Handler) Complete(w http.ResponseWriter, r *http.Request) {
	var req completeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.MFAToken == "" || req.Code == "" {
		writeJSONError(w, "mfa_token and code required", http.StatusBadRequest)
		return
	}
	out, err := h.completeUseCase.Execute(r.Context(), mfaapp.CompleteInput{
		MFAToken: req.MFAToken,
		Code:     req.Code,
	})
	if err != nil {
		writeJSONError(w, "invalid mfa challenge or code", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	factors, err := h.totpService.List(r.Context(), p.IdentityID)
	if err != nil {
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	type out struct {
		ID         string `json:"id"`
		FactorType string `json:"factor_type"`
		Label      string `json:"label"`
		Verified   bool   `json:"verified"`
	}
	resp := make([]out, 0, len(factors))
	for _, f := range factors {
		resp = append(resp, out{f.ID, f.FactorType, f.Label, f.Verified})
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, msg string, status int) {
	writeJSON(w, status, map[string]string{"error": msg})
}
