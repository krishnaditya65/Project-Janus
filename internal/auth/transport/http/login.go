package http

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	authapp "github.com/krishnaditya65/auth-server/internal/auth/app"
	sharederrors "github.com/krishnaditya65/auth-server/internal/shared/errors"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Login(
	w http.ResponseWriter,
	r *http.Request,
) {

	var req LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	result, err := h.loginUseCase.Execute(
		r.Context(),
		authapp.LoginInput{
			Email:     req.Email,
			Password:  req.Password,
			IPAddress: extractIP(r),
			UserAgent: r.UserAgent(),
		},
	)

	if err != nil {
		if err == sharederrors.ErrInvalidCredentials {
			writeError(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if err == authapp.ErrMFAEnrollmentRequired {
			writeError(w, "mfa enrollment required", http.StatusForbidden)
			return
		}
		writeError(w, "internal error", http.StatusInternalServerError)
		return
	}

	setRefreshCookie(w, result.RefreshToken)
	writeJSON(w, result)
}

// extractIP returns the client IP from the request.
// Checks X-Forwarded-For and X-Real-IP before falling back to RemoteAddr.
// The sessions.ip_address column is text, so this returns a plain string.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if first != "" {
			return first
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	if addrPort, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return addrPort.Addr().String()
	}

	return r.RemoteAddr
}
