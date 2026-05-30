package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const oauthRedirectURI = "http://localhost:3000/callback"

var clientCounter int64

// makeOAuthClient creates a per-tenant client and returns its id.
func makeOAuthClient(t *testing.T, c *Client) string {
	t.Helper()
	n := atomic.AddInt64(&clientCounter, 1)
	cid := fmt.Sprintf("itest-c-%d-%s", n, UniqueEmail("")[:8])
	return CreateOAuthClientForTenant(t, c.TenantID, cid)
}

func TestOAuth_AuthorizeAndTokenFlow(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "oauth")
	clientID := makeOAuthClient(t, c)

	verifier, challenge := PKCEPair()
	code := authorizeAndGetCode(t, c, clientID, challenge, "the-nonce", "the-state")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {oauthRedirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	resp, body := c.PostForm("/oauth/token", form)
	MustStatus(t, resp, body, 200, "token exchange")

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" {
		t.Error("no access_token")
	}
	if tok.IDToken == "" {
		t.Error("no id_token (openid scope was requested)")
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in not positive: %d", tok.ExpiresIn)
	}
}

func TestOAuth_PKCEWrongVerifierRejected(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "pkce")
	clientID := makeOAuthClient(t, c)

	_, challenge := PKCEPair()
	code := authorizeAndGetCode(t, c, clientID, challenge, "", "s")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {oauthRedirectURI},
		"client_id":     {clientID},
		"code_verifier": {"wrong-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	resp, _ := c.PostForm("/oauth/token", form)
	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for wrong verifier, got %d", resp.StatusCode)
	}
}

func TestOAuth_CodeReuseRejected(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "reuse")
	clientID := makeOAuthClient(t, c)
	verifier, challenge := PKCEPair()
	code := authorizeAndGetCode(t, c, clientID, challenge, "", "s")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {oauthRedirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	resp, _ := c.PostForm("/oauth/token", form)
	if resp.StatusCode != 200 {
		t.Fatalf("first exchange should succeed, got %d", resp.StatusCode)
	}
	resp2, _ := c.PostForm("/oauth/token", form)
	if resp2.StatusCode != 400 {
		t.Errorf("code reuse expected 400, got %d", resp2.StatusCode)
	}
}

func TestOAuth_MissingPKCERedirectsWithError(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "nopkce")
	clientID := makeOAuthClient(t, c)
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {oauthRedirectURI},
		"scope":         {"openid"},
		"state":         {"s"},
	}
	noFollow := *c.http
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequest("GET", c.baseURL+"/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-Session-ID", c.SessionID)
	resp, _ := noFollow.Do(req)
	if resp.StatusCode != 302 {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Errorf("expected error= in redirect %s", loc)
	}
}

func TestOAuth_RefreshTokenGrant(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "rt-grant")
	clientID := makeOAuthClient(t, c)
	verifier, challenge := PKCEPair()
	code := authorizeAndGetCode(t, c, clientID, challenge, "", "s")

	resp, body := c.PostForm("/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {oauthRedirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	MustStatus(t, resp, body, 200, "code grant")
	var tok struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(body, &tok)

	resp2, body2 := c.PostForm("/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
		"client_id":     {clientID},
	})
	MustStatus(t, resp2, body2, 200, "refresh grant")
	var tok2 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(body2, &tok2)
	if tok2.AccessToken == "" {
		t.Error("refresh grant missing access_token")
	}
	if tok2.RefreshToken == tok.RefreshToken {
		t.Error("refresh grant did not rotate refresh token")
	}
}

func TestOIDC_UserInfo(t *testing.T) {
	requiresServer(t)
	c := authedClient(t, "userinfo")
	resp, body := c.Get("/oauth/userinfo")
	MustStatus(t, resp, body, 200, "userinfo")
	var u struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	_ = json.Unmarshal(body, &u)
	if u.Sub == "" {
		t.Error("userinfo missing sub")
	}
	if u.Email != c.Email {
		t.Errorf("userinfo email mismatch: got %s want %s", u.Email, c.Email)
	}
}

// authedClient registers + logs in a fresh user and returns the client.
func authedClient(t *testing.T, prefix string) *Client {
	t.Helper()
	c := New(t)
	c.Register(UniqueEmail(prefix), "password123", prefix+" Tenant")
	c.Login(c.Email, "password123")
	return c
}

func authorizeAndGetCode(t *testing.T, c *Client, clientID, challenge, nonce, state string) string {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {oauthRedirectURI},
		"scope":                 {"openid"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if nonce != "" {
		q.Set("nonce", nonce)
	}
	noFollow := *c.http
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequest("GET", c.baseURL+"/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-Session-ID", c.SessionID)
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("authorize expected 302, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", resp.Header.Get("Location"))
	}
	return code
}
