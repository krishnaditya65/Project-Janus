package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	mfadomain "github.com/krishnaditya65/Project-Janus/internal/mfa/domain"
)

// CreateFactor handles POST /internal/mfa/factors. The request body is the
// full mfadomain.Factor: callers already generate ID/timestamps client-side
// before calling Repository.Create, mirroring identity-service's
// CreateIdentity.
func (h *InternalHandler) CreateFactor(w http.ResponseWriter, r *http.Request) {
	var factor mfadomain.Factor
	if err := json.NewDecoder(r.Body).Decode(&factor); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := h.factorRepo.Create(r.Context(), &factor); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(factor)
}

// GetFactorByID handles GET /internal/mfa/factors/{id}.
func (h *InternalHandler) GetFactorByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	factor, err := h.factorRepo.GetByID(r.Context(), id)
	if err != nil {
		http.Error(w, "factor not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(factor)
}

// GetFactorsByIdentity handles GET /internal/mfa/factors/by-identity?identity_id=...
func (h *InternalHandler) GetFactorsByIdentity(w http.ResponseWriter, r *http.Request) {
	identityID := r.URL.Query().Get("identity_id")
	if identityID == "" {
		http.Error(w, "identity_id is required", http.StatusBadRequest)
		return
	}

	factors, err := h.factorRepo.GetByIdentity(r.Context(), identityID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(factors)
}

// GetVerifiedFactorsByIdentity handles GET /internal/mfa/factors/verified?identity_id=...
// This is the endpoint backing mfadomain.Repository.GetVerifiedByIdentity,
// which is what auth's LoginUseCase calls today.
func (h *InternalHandler) GetVerifiedFactorsByIdentity(w http.ResponseWriter, r *http.Request) {
	identityID := r.URL.Query().Get("identity_id")
	if identityID == "" {
		http.Error(w, "identity_id is required", http.StatusBadRequest)
		return
	}

	factors, err := h.factorRepo.GetVerifiedByIdentity(r.Context(), identityID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(factors)
}

// MarkFactorVerified handles POST /internal/mfa/factors/{id}/verify.
func (h *InternalHandler) MarkFactorVerified(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.factorRepo.MarkVerified(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeleteFactor handles DELETE /internal/mfa/factors/{id}.
func (h *InternalHandler) DeleteFactor(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := h.factorRepo.Delete(r.Context(), id); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
