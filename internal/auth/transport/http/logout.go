package http

import (
	"net/http"

	authapp "github.com/krishnaditya65/Project-Janus/internal/auth/app"
	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
)

func (h *Handler) Logout(
	w http.ResponseWriter,
	r *http.Request,
) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	err := h.logoutUseCase.Execute(r.Context(), authapp.LogoutInput{
		SessionID: p.SessionID,
	})
	if err != nil {
		writeError(w, "internal error", http.StatusInternalServerError)
		return
	}

	clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
