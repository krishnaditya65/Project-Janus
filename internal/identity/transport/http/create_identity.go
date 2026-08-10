package http

import (
	"encoding/json"
	"net/http"

	identitydomain "github.com/krishnaditya65/Project-Janus/internal/identity/domain"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

// CreateIdentity handles POST /internal/identities.
//
// Unlike CreateUser (which decodes a request-specific DTO), the request body
// here is the full identitydomain.Identity: callers such as auth's
// RegisterUseCase already generate ID/status/timestamps client-side before
// calling Repository.Create, and identity-service must persist exactly what
// it was given (see PersistIdentityUseCase) for the round-trip to be
// lossless.
func (h *IdentityHandler) CreateIdentity(
	w http.ResponseWriter,
	r *http.Request,
) {

	var identity identitydomain.Identity

	if err := json.NewDecoder(r.Body).Decode(&identity); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := h.persistUseCase.Execute(r.Context(), &identity); err != nil {
		if err == sharederrors.ErrConflict {
			http.Error(w, "email already exists", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(identity)
}
