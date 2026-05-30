// Stress test: hammer the auth server with concurrent traffic and report
// throughput + latency percentiles per scenario.
//
// Scenarios:
//   - login          : POST /login (password verify + DB write + JWT sign per request)
//   - jwt-verify     : GET  /me with a Bearer JWT (stateless verify, no DB)
//   - session-auth   : GET  /me with X-Session-ID  (4 sequential DB reads)
//   - jwks           : GET  /.well-known/jwks.json (cacheable read)
//   - oauth-token    : POST /oauth/token authorization_code grant (full handshake)
//   - mixed          : 70% jwt-verify / 20% login / 10% jwks
//
// Usage:
//
//	go run ./test/stress -scenario login -concurrency 100 -duration 30s
//	go run ./test/stress -scenario mixed -concurrency 200 -duration 60s
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	flagScenario    = flag.String("scenario", "mixed", "login | jwt-verify | session-auth | jwks | oauth-token | mixed")
	flagConcurrency = flag.Int("concurrency", 50, "concurrent workers")
	flagDuration    = flag.Duration("duration", 15*time.Second, "test duration")
	flagBase        = flag.String("base", "http://localhost:8080", "base URL")
	flagDB          = flag.String("db", "postgres://authadmin:authpassword@localhost:5433/authserver?sslmode=disable", "postgres DSN for setup")
	flagWarmup      = flag.Duration("warmup", 1*time.Second, "warmup before measuring")

	// SLA budgets: any p95/p99/failure-rate set to 0 is "do not assert".
	// When any are non-zero, the process exits non-zero if the budget is breached.
	flagSLAp95     = flag.Duration("sla-p95", 0, "fail if p95 latency > this")
	flagSLAp99     = flag.Duration("sla-p99", 0, "fail if p99 latency > this")
	flagSLAFailPct = flag.Float64("sla-fail-pct", 0, "fail if failure rate (percent) > this")
	flagSLAMinRPS  = flag.Float64("sla-min-rps", 0, "fail if throughput < this")
)

type result struct {
	durations []time.Duration
	ok        int64
	fail      int64
	mu        sync.Mutex
}

func (r *result) record(d time.Duration, ok bool) {
	r.mu.Lock()
	r.durations = append(r.durations, d)
	r.mu.Unlock()
	if ok {
		atomic.AddInt64(&r.ok, 1)
	} else {
		atomic.AddInt64(&r.fail, 1)
	}
}

func main() {
	flag.Parse()

	if err := waitForServer(*flagBase); err != nil {
		fmt.Fprintf(os.Stderr, "server not ready: %v\n", err)
		os.Exit(1)
	}

	// Set up a shared test user.
	email := fmt.Sprintf("stress-%d@test.local", time.Now().UnixNano())
	password := "stress-password-123"
	if err := registerUser(*flagBase, email, password); err != nil {
		fmt.Fprintf(os.Stderr, "register: %v\n", err)
		os.Exit(1)
	}
	login, err := loginUser(*flagBase, email, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login: %v\n", err)
		os.Exit(1)
	}

	// Set up OAuth client if needed
	var oauthClientID string
	if *flagScenario == "oauth-token" {
		oauthClientID, err = createOAuthClient(*flagDB, login.TenantID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create oauth client: %v\n", err)
			os.Exit(1)
		}
	}

	scenarios := map[string]func() (time.Duration, bool){
		"login":        func() (time.Duration, bool) { return runLogin(*flagBase, email, password) },
		"jwt-verify":   func() (time.Duration, bool) { return runJWTVerify(*flagBase, login.AccessToken) },
		"session-auth": func() (time.Duration, bool) { return runSessionAuth(*flagBase, login.SessionID) },
		"jwks":         func() (time.Duration, bool) { return runJWKS(*flagBase) },
		"oauth-token":  func() (time.Duration, bool) { return runOAuthToken(*flagBase, oauthClientID, login.SessionID) },
		"mixed": func() (time.Duration, bool) {
			n := rand.Intn(100)
			if n < 70 {
				return runJWTVerify(*flagBase, login.AccessToken)
			} else if n < 90 {
				return runLogin(*flagBase, email, password)
			}
			return runJWKS(*flagBase)
		},
	}

	fn, ok := scenarios[*flagScenario]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown scenario %q\n", *flagScenario)
		os.Exit(1)
	}

	fmt.Printf("Stress test\n")
	fmt.Printf("  scenario:    %s\n", *flagScenario)
	fmt.Printf("  concurrency: %d\n", *flagConcurrency)
	fmt.Printf("  duration:    %s\n", *flagDuration)
	fmt.Printf("  base URL:    %s\n", *flagBase)
	fmt.Printf("  warmup:      %s\n", *flagWarmup)
	fmt.Println()

	// Warm up
	if *flagWarmup > 0 {
		warmupRes := &result{}
		runFor(*flagWarmup, *flagConcurrency, fn, warmupRes)
	}

	res := &result{}
	start := time.Now()
	runFor(*flagDuration, *flagConcurrency, fn, res)
	elapsed := time.Since(start)

	report(res, elapsed)
}

func runFor(d time.Duration, workers int, fn func() (time.Duration, bool), res *result) {
	stop := time.NewTimer(d)
	defer stop.Stop()

	var wg sync.WaitGroup
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				dur, ok := fn()
				res.record(dur, ok)
			}
		}()
	}
	<-stop.C
	close(done)
	wg.Wait()
}

func report(res *result, elapsed time.Duration) {
	res.mu.Lock()
	durations := res.durations
	res.mu.Unlock()

	total := len(durations)
	if total == 0 {
		fmt.Println("no samples")
		return
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	pct := func(p float64) time.Duration {
		idx := int(float64(total)*p) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= total {
			idx = total - 1
		}
		return durations[idx]
	}
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}

	throughput := float64(total) / elapsed.Seconds()

	fmt.Println("Results")
	fmt.Println("=======")
	fmt.Printf("  duration:    %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  total req:   %d\n", total)
	fmt.Printf("  ok:          %d\n", atomic.LoadInt64(&res.ok))
	fmt.Printf("  fail:        %d\n", atomic.LoadInt64(&res.fail))
	fmt.Printf("  throughput:  %.1f req/s\n", throughput)
	fmt.Println("Latency")
	fmt.Printf("  min:         %s\n", durations[0])
	fmt.Printf("  p50:         %s\n", pct(0.50))
	fmt.Printf("  p90:         %s\n", pct(0.90))
	fmt.Printf("  p95:         %s\n", pct(0.95))
	fmt.Printf("  p99:         %s\n", pct(0.99))
	fmt.Printf("  max:         %s\n", durations[total-1])
	fmt.Printf("  mean:        %s\n", sum/time.Duration(total))

	failPct := float64(atomic.LoadInt64(&res.fail)) / float64(total) * 100

	// SLA assertions
	breaches := []string{}
	if *flagSLAp95 > 0 && pct(0.95) > *flagSLAp95 {
		breaches = append(breaches, fmt.Sprintf("p95 %s > budget %s", pct(0.95), *flagSLAp95))
	}
	if *flagSLAp99 > 0 && pct(0.99) > *flagSLAp99 {
		breaches = append(breaches, fmt.Sprintf("p99 %s > budget %s", pct(0.99), *flagSLAp99))
	}
	if *flagSLAFailPct > 0 && failPct > *flagSLAFailPct {
		breaches = append(breaches, fmt.Sprintf("failure rate %.2f%% > budget %.2f%%", failPct, *flagSLAFailPct))
	}
	if *flagSLAMinRPS > 0 && throughput < *flagSLAMinRPS {
		breaches = append(breaches, fmt.Sprintf("throughput %.1f req/s < budget %.1f", throughput, *flagSLAMinRPS))
	}

	if len(breaches) > 0 {
		fmt.Println("\nSLA BREACH")
		for _, b := range breaches {
			fmt.Printf("  - %s\n", b)
		}
		os.Exit(2)
	}
	if failPct > 1.0 && *flagSLAFailPct == 0 {
		fmt.Printf("\nFAILURE RATE %.2f%% > default 1%% threshold\n", failPct)
		os.Exit(2)
	}
}

// ---- Scenario implementations ----

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		IdleConnTimeout:     90 * time.Second,
	},
}

func runJWTVerify(base, token string) (time.Duration, bool) {
	t0 := time.Now()
	req, _ := http.NewRequest("GET", base+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	dur := time.Since(t0)
	if err != nil {
		return dur, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return dur, resp.StatusCode == 200
}

func runSessionAuth(base, sessionID string) (time.Duration, bool) {
	t0 := time.Now()
	req, _ := http.NewRequest("GET", base+"/me", nil)
	req.Header.Set("X-Session-ID", sessionID)
	resp, err := httpClient.Do(req)
	dur := time.Since(t0)
	if err != nil {
		return dur, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return dur, resp.StatusCode == 200
}

func runJWKS(base string) (time.Duration, bool) {
	t0 := time.Now()
	resp, err := httpClient.Get(base + "/.well-known/jwks.json")
	dur := time.Since(t0)
	if err != nil {
		return dur, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return dur, resp.StatusCode == 200
}

func runLogin(base, email, password string) (time.Duration, bool) {
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	t0 := time.Now()
	resp, err := httpClient.Post(base+"/login", "application/json", body)
	dur := time.Since(t0)
	if err != nil {
		return dur, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return dur, resp.StatusCode == 200
}

func runOAuthToken(base, clientID, sessionID string) (time.Duration, bool) {
	// Authorize
	verifier := uuid.NewString() + uuid.NewString()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"scope":                 {"openid"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	noFollow := &http.Client{
		Timeout:       30 * time.Second,
		Transport:     httpClient.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t0 := time.Now()
	req, _ := http.NewRequest("GET", base+"/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-Session-ID", sessionID)
	resp, err := noFollow.Do(req)
	if err != nil {
		return time.Since(t0), false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 302 {
		return time.Since(t0), false
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		return time.Since(t0), false
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	resp2, err := httpClient.PostForm(base+"/oauth/token", form)
	dur := time.Since(t0)
	if err != nil {
		return dur, false
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	return dur, resp2.StatusCode == 200
}

// ---- Setup helpers ----

func waitForServer(base string) error {
	for i := 0; i < 20; i++ {
		resp, err := http.Get(base + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("server at %s did not respond after 5s", base)
}

func registerUser(base, email, password string) error {
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q,"tenant_name":"Stress"}`, email, password))
	resp, err := http.Post(base+"/register", "application/json", body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		return fmt.Errorf("register status %d", resp.StatusCode)
	}
	return nil
}

type loginInfo struct {
	AccessToken string `json:"access_token"`
	SessionID   string `json:"session_id"`
	TenantID    string `json:"tenant_id"`
}

func loginUser(base, email, password string) (*loginInfo, error) {
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	resp, err := http.Post(base+"/login", "application/json", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("login status %d", resp.StatusCode)
	}
	li := &loginInfo{}
	if err := json.NewDecoder(resp.Body).Decode(li); err != nil {
		return nil, err
	}
	return li, nil
}

func createOAuthClient(dsn, tenantID string) (string, error) {
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return "", err
	}
	defer pool.Close()
	cid := fmt.Sprintf("stress-%d", time.Now().UnixNano())
	_, err = pool.Exec(context.Background(), `
		INSERT INTO oauth_clients (id, tenant_id, client_id, client_name, redirect_uris, grant_types, scopes, confidential)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, false)`,
		uuid.NewString(), tenantID, cid, "Stress",
		`["http://localhost:3000/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["openid","profile","email"]`)
	if err != nil {
		return "", err
	}
	return cid, nil
}
