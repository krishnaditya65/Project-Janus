package http

import (
	"encoding/json"
	"net/http"

	authapp "github.com/krishnaditya65/Project-Janus/internal/auth/app"
	sharederrors "github.com/krishnaditya65/Project-Janus/internal/shared/errors"
)

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest

	tokenFromCookie := ""
	if c, err := r.Cookie(refreshCookieName); err == nil {
		tokenFromCookie = c.Value
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && tokenFromCookie == "" {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		req.RefreshToken = tokenFromCookie
	}

	if req.RefreshToken == "" {
		writeError(w, "refresh_token required", http.StatusBadRequest)
		return
	}

	result, err := h.refreshUseCase.Execute(r.Context(), authapp.RefreshInput{
		RefreshToken: req.RefreshToken,
	})

	if err != nil {
		if err == sharederrors.ErrUnauthorized {
			writeError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		writeError(w, "internal error", http.StatusInternalServerError)
		return
	}

	setRefreshCookie(w, result.RefreshToken)
	writeJSON(w, result)
}
