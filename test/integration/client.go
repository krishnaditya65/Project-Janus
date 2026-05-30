package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func BaseURL() string {
	if u := os.Getenv("AUTH_BASE_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

// Client is a thin HTTP wrapper that captures auth state across calls.
type Client struct {
	t       *testing.T
	http    *http.Client
	baseURL string

	AccessToken  string
	RefreshToken string
	SessionID    string
	TenantID     string
	UserID       string
	Email        string
}

func New(t *testing.T) *Client {
	t.Helper()
	return &Client{
		t:       t,
		http:    &http.Client{Timeout: 10 * time.Second},
		baseURL: BaseURL(),
	}
}

func (c *Client) do(method, path string, body any, headers map[string]string) (*http.Response, []byte) {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			reader = strings.NewReader(b)
		case []byte:
			reader = bytes.NewReader(b)
		case url.Values:
			reader = strings.NewReader(b.Encode())
		default:
			buf, _ := json.Marshal(b)
			reader = bytes.NewReader(buf)
		}
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		c.t.Fatalf("build request: %v", err)
	}
	if body != nil {
		switch body.(type) {
		case url.Values:
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		default:
			req.Header.Set("Content-Type", "application/json")
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("http error: %v", err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	return resp, buf
}

func (c *Client) Register(email, password, tenantName string) {
	c.t.Helper()
	c.Email = email
	resp, body := c.do("POST", "/register", map[string]string{
		"email": email, "password": password, "tenant_name": tenantName,
	}, nil)
	if resp.StatusCode != 201 {
		c.t.Fatalf("register: status %d, body %s", resp.StatusCode, body)
	}
}

type loginResp struct {
	SessionID    string `json:"session_id"`
	TenantID     string `json:"tenant_id"`
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	MFARequired  bool   `json:"mfa_required"`
	MFAToken     string `json:"mfa_token"`
}

func (c *Client) Login(email, password string) loginResp {
	c.t.Helper()
	resp, body := c.do("POST", "/login", map[string]string{"email": email, "password": password}, nil)
	if resp.StatusCode != 200 {
		c.t.Fatalf("login: status %d, body %s", resp.StatusCode, body)
	}
	var lr loginResp
	if err := json.Unmarshal(body, &lr); err != nil {
		c.t.Fatalf("decode login: %v", err)
	}
	c.AccessToken = lr.AccessToken
	c.RefreshToken = lr.RefreshToken
	c.SessionID = lr.SessionID
	c.TenantID = lr.TenantID
	c.UserID = lr.UserID
	c.Email = email
	return lr
}

func (c *Client) LoginExpect(email, password string, expectedStatus int) {
	c.t.Helper()
	resp, body := c.do("POST", "/login", map[string]string{"email": email, "password": password}, nil)
	if resp.StatusCode != expectedStatus {
		c.t.Fatalf("login expected %d, got %d: %s", expectedStatus, resp.StatusCode, body)
	}
}

func (c *Client) Get(path string) (*http.Response, []byte) {
	c.t.Helper()
	headers := map[string]string{}
	if c.AccessToken != "" {
		headers["Authorization"] = "Bearer " + c.AccessToken
	}
	return c.do("GET", path, nil, headers)
}

func (c *Client) Post(path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	headers := map[string]string{}
	if c.AccessToken != "" {
		headers["Authorization"] = "Bearer " + c.AccessToken
	}
	return c.do("POST", path, body, headers)
}

func (c *Client) PostForm(path string, form url.Values) (*http.Response, []byte) {
	c.t.Helper()
	return c.do("POST", path, form, nil)
}

func MustStatus(t *testing.T, resp *http.Response, body []byte, want int, msg string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s: expected status %d, got %d, body=%s", msg, want, resp.StatusCode, body)
	}
}

func PKCEPair() (verifier, challenge string) {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = byte(time.Now().UnixNano() >> i)
	}
	verifier = base64.RawURLEncoding.EncodeToString(bytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// UniqueEmail returns an email guaranteed unique across test runs.
func UniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@itest.local", prefix, time.Now().UnixNano())
}
