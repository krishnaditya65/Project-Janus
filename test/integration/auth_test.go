package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// requiresServer skips the test if the auth server isn't reachable.
func requiresServer(t *testing.T) {
	t.Helper()
	c := New(t)
	resp, _ := c.do("GET", "/health", nil, nil)
	if resp.StatusCode != 200 {
		t.Skipf("auth server not reachable at %s", c.baseURL)
	}
}

func TestRegisterLoginMe(t *testing.T) {
	requiresServer(t)
	c := New(t)
	email := UniqueEmail("auth")
	c.Register(email, "password123", "Auth Test")
	c.Login(email, "password123")

	if c.AccessToken == "" {
		t.Fatal("no access token after login")
	}
	resp, body := c.Get("/me")
	MustStatus(t, resp, body, 200, "/me with bearer")

	var me map[string]any
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("decode /me: %v", err)
	}
	if me["Email"] != email {
		t.Errorf("expected Email=%s, got %v", email, me["Email"])
	}
}

func TestSessionIDFallbackAuth(t *testing.T) {
	requiresServer(t)
	c := New(t)
	email := UniqueEmail("session")
	c.Register(email, "password123", "Session Fallback")
	c.Login(email, "password123")

	resp, _ := c.do("GET", "/me", nil, map[string]string{
		"X-Session-ID": c.SessionID,
	})
	if resp.StatusCode != 200 {
		t.Errorf("session-id fallback should authenticate: got %d", resp.StatusCode)
	}
}

func TestRefreshRotatesAndInvalidatesOld(t *testing.T) {
	requiresServer(t)
	c := New(t)
	email := UniqueEmail("refresh")
	c.Register(email, "password123", "Refresh Test")
	c.Login(email, "password123")
	oldRefresh := c.RefreshToken

	resp, body := c.do("POST", "/refresh", map[string]string{"refresh_token": oldRefresh}, nil)
	MustStatus(t, resp, body, 200, "refresh 1")

	var r loginResp
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	if r.RefreshToken == oldRefresh {
		t.Error("refresh did not rotate the token")
	}
	if r.AccessToken == "" {
		t.Error("refresh did not issue a new access token")
	}

	resp2, body2 := c.do("POST", "/refresh", map[string]string{"refresh_token": oldRefresh}, nil)
	if resp2.StatusCode != 401 {
		t.Errorf("reusing old refresh should fail: got %d, body=%s", resp2.StatusCode, body2)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	requiresServer(t)
	c := New(t)
	email := UniqueEmail("logout")
	c.Register(email, "password123", "Logout Test")
	c.Login(email, "password123")

	resp, body := c.Post("/logout", nil)
	MustStatus(t, resp, body, 204, "logout")

	resp2, _ := c.do("GET", "/me", nil, map[string]string{"X-Session-ID": c.SessionID})
	if resp2.StatusCode != 401 {
		t.Errorf("session should be invalid after logout: got %d", resp2.StatusCode)
	}
}

func TestRegisterValidation(t *testing.T) {
	requiresServer(t)
	c := New(t)
	cases := []struct {
		name           string
		email, pass    string
		expectedStatus int
	}{
		{"bad email", "no-at-sign", "password123", 400},
		{"short password", UniqueEmail("short"), "abc", 400},
		{"missing email", "", "password123", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := c.do("POST", "/register", map[string]string{
				"email": tc.email, "password": tc.pass, "tenant_name": "x",
			}, nil)
			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected %d, got %d body=%s", tc.expectedStatus, resp.StatusCode, body)
			}
		})
	}
}

func TestJWKSEndpoint(t *testing.T) {
	requiresServer(t)
	c := New(t)
	resp, body := c.do("GET", "/.well-known/jwks.json", nil, nil)
	MustStatus(t, resp, body, 200, "jwks")

	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(cc, "max-age=") {
		t.Errorf("expected Cache-Control max-age, got %q", cc)
	}

	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("no keys in JWKS")
	}
	k := jwks.Keys[0]
	for _, field := range []string{"kty", "kid", "alg", "use"} {
		if k[field] == nil {
			t.Errorf("JWK missing %s", field)
		}
	}
}

func TestDiscoveryEndpoint(t *testing.T) {
	requiresServer(t)
	c := New(t)
	resp, body := c.do("GET", "/.well-known/openid-configuration", nil, nil)
	MustStatus(t, resp, body, 200, "discovery")

	var d map[string]any
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"issuer", "authorization_endpoint", "token_endpoint",
		"userinfo_endpoint", "jwks_uri", "code_challenge_methods_supported"} {
		if d[field] == nil {
			t.Errorf("discovery missing %s", field)
		}
	}
}

func TestUnauthorizedAccess(t *testing.T) {
	requiresServer(t)
	c := New(t)
	for _, path := range []string{"/me", "/users", "/roles", "/mfa/factors", "/webauthn/credentials"} {
		resp, _ := c.do("GET", path, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s expected 401, got %d", path, resp.StatusCode)
		}
	}
}
