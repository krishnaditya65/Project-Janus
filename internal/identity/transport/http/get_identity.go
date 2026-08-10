package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"
)

// GetIdentityByEmail handles GET /internal/identities/by-email?email=...
func (h *IdentityHandler) GetIdentityByEmail(
	w http.ResponseWriter,
	r *http.Request,
) {

	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}

	identity, err := h.getByEmailUseCase.Execute(
		r.Context(),
		identityapp.GetIdentityByEmailInput{
			Email: email,
		},
	)

	if err != nil {
		http.Error(w, "identity not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(identity)
}

// GetIdentityByID handles GET /internal/identities/{id}
func (h *IdentityHandler) GetIdentityByID(
	w http.ResponseWriter,
	r *http.Request,
) {

	identityID := chi.URLParam(r, "id")

	identity, err := h.getByIDUseCase.Execute(
		r.Context(),
		identityapp.GetIdentityByIDInput{
			ID: identityID,
		},
	)

	if err != nil {
		http.Error(w, "identity not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(identity)
}
