package http

import (
	"encoding/json"
	"net/http"

	authctx "github.com/krishnaditya65/Project-Janus/internal/shared/context"
	tenantapp "github.com/krishnaditya65/Project-Janus/internal/tenant/app"
	tenantdomain "github.com/krishnaditya65/Project-Janus/internal/tenant/domain"
)

type PolicyHandler struct {
	enforcer *tenantapp.PolicyEnforcer
	repo     tenantdomain.PolicyRepository
}

func NewPolicyHandler(enforcer *tenantapp.PolicyEnforcer, repo tenantdomain.PolicyRepository) *PolicyHandler {
	return &PolicyHandler{enforcer: enforcer, repo: repo}
}

type policyDTO struct {
	PasswordMinLength     int      `json:"password_min_length"`
	PasswordRequireUpper  bool     `json:"password_require_upper"`
	PasswordRequireDigit  bool     `json:"password_require_digit"`
	PasswordRequireSymbol bool     `json:"password_require_symbol"`
	AllowedEmailDomains   []string `json:"allowed_email_domains"`
	RequireMFA            bool     `json:"require_mfa"`
	MaxActiveSessions     int      `json:"max_active_sessions"`
}

// GET /tenant/policy — returns the policy for the caller's tenant.
func (h *PolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	pol, err := h.enforcer.Get(r.Context(), p.TenantID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toDTO(pol))
}

// PUT /tenant/policy — full upsert; requires "tenant:update" permission.
func (h *PolicyHandler) Put(w http.ResponseWriter, r *http.Request) {
	p, ok := authctx.Principal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var dto policyDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	policy := &tenantdomain.Policy{
		TenantID:              p.TenantID,
		PasswordMinLength:     dto.PasswordMinLength,
		PasswordRequireUpper:  dto.PasswordRequireUpper,
		PasswordRequireDigit:  dto.PasswordRequireDigit,
		PasswordRequireSymbol: dto.PasswordRequireSymbol,
		AllowedEmailDomains:   dto.AllowedEmailDomains,
		RequireMFA:            dto.RequireMFA,
		MaxActiveSessions:     dto.MaxActiveSessions,
	}
	if policy.PasswordMinLength <= 0 {
		policy.PasswordMinLength = 8
	}
	if err := h.repo.Upsert(r.Context(), policy); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, toDTO(policy))
}

func toDTO(p *tenantdomain.Policy) policyDTO {
	return policyDTO{
		PasswordMinLength:     p.PasswordMinLength,
		PasswordRequireUpper:  p.PasswordRequireUpper,
		PasswordRequireDigit:  p.PasswordRequireDigit,
		PasswordRequireSymbol: p.PasswordRequireSymbol,
		AllowedEmailDomains:   p.AllowedEmailDomains,
		RequireMFA:            p.RequireMFA,
		MaxActiveSessions:     p.MaxActiveSessions,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
