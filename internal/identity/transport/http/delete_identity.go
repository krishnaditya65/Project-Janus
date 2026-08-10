package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	identityapp "github.com/krishnaditya65/Project-Janus/internal/identity/app"
)

// DeleteIdentity handles DELETE /internal/identities/{id}. It backs the
// compensating-delete path used by callers that persisted an Identity here
// but then failed a subsequent step in their own local transaction (see
// internal/identity/infra/httpclient's Delete).
func (h *IdentityHandler) DeleteIdentity(
	w http.ResponseWriter,
	r *http.Request,
) {

	identityID := chi.URLParam(r, "id")

	if err := h.deleteUseCase.Execute(
		r.Context(),
		identityapp.DeleteIdentityInput{
			ID: identityID,
		},
	); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
