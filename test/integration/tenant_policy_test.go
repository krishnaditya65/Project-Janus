package integration

import (
	"encoding/json"
	"testing"
)

func TestTenantPolicy_GetReturnsDefaults(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "policy-get")
	resp, body := c.Get("/tenant/policy")
	MustStatus(t, resp, body, 200, "GET /tenant/policy")
	var dto map[string]any
	_ = json.Unmarshal(body, &dto)
	if int(dto["password_min_length"].(float64)) != 8 {
		t.Errorf("expected default password_min_length=8, got %v", dto["password_min_length"])
	}
	if dto["require_mfa"].(bool) {
		t.Error("expected require_mfa=false by default")
	}
}

func TestTenantPolicy_PutUpdates(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "policy-put")
	resp, body := c.Post("/tenant/policy", map[string]any{
		"password_min_length":     12,
		"password_require_digit":  true,
		"password_require_symbol": true,
		"allowed_email_domains":   []string{"company.com"},
		"require_mfa":             true,
	})
	// chi PUT helper not in our Client; use raw do
	_ = resp; _ = body
	resp2, body2 := c.do("PUT", "/tenant/policy", map[string]any{
		"password_min_length":     12,
		"password_require_digit":  true,
		"password_require_symbol": true,
		"allowed_email_domains":   []string{"company.com"},
		"require_mfa":             true,
	}, map[string]string{"Authorization": "Bearer " + c.AccessToken})
	MustStatus(t, resp2, body2, 200, "PUT /tenant/policy")
}

func TestTenantPolicy_RequireMFA_BlocksLoginWithoutFactor(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "mfa-required")
	// Turn on require_mfa for this tenant.
	resp, body := c.do("PUT", "/tenant/policy", map[string]any{
		"password_min_length": 8,
		"require_mfa":         true,
	}, map[string]string{"Authorization": "Bearer " + c.AccessToken})
	MustStatus(t, resp, body, 200, "PUT policy require_mfa=true")

	// New login attempt must now fail with 403 mfa enrollment required.
	c2 := New(t)
	resp2, body2 := c2.do("POST", "/login", map[string]string{
		"email": c.Email, "password": "password123",
	}, nil)
	if resp2.StatusCode != 403 {
		t.Errorf("expected 403 mfa enrollment required, got %d body=%s", resp2.StatusCode, body2)
	}
}

func TestMetrics_EndpointReturnsPrometheusFormat(t *testing.T) {
	requiresServer(t)
	c := New(t)
	resp, body := c.do("GET", "/metrics", nil, nil)
	MustStatus(t, resp, body, 200, "GET /metrics")
	ct := resp.Header.Get("Content-Type")
	if !startsWith(ct, "text/plain") && !startsWith(ct, "application/openmetrics") {
		t.Errorf("unexpected content-type: %s", ct)
	}
	// Should have at least one of our counters
	if !contains(body, "auth_http_requests_total") {
		t.Error("expected auth_http_requests_total in /metrics output")
	}
}

func TestPrincipalCache_HitMissCounters(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "cache")
	// Make two session-id calls; first should miss, second should hit.
	c.do("GET", "/me", nil, map[string]string{"X-Session-ID": c.SessionID})
	c.do("GET", "/me", nil, map[string]string{"X-Session-ID": c.SessionID})

	resp, body := c.do("GET", "/metrics", nil, nil)
	MustStatus(t, resp, body, 200, "metrics")
	if !contains(body, "auth_principal_cache_hits_total") {
		t.Error("missing principal_cache_hits counter")
	}
	if !contains(body, "auth_principal_cache_misses_total") {
		t.Error("missing principal_cache_misses counter")
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
func contains(b []byte, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == sub {
			return true
		}
	}
	return false
}
