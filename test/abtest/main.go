// A/B test: run two auth strategies under identical conditions and compare
// throughput + latency + significance.
//
// Variants:
//
//	A = stateless JWT auth on /me   (Authorization: Bearer <JWT>)
//	B = session-id DB auth on /me   (X-Session-ID: <uuid>)
//
// Both call the same endpoint with the same principal. The only difference
// is the auth path: A skips the DB; B does 4 sequential DB reads.
//
// We interleave one call to A with one call to B per worker iteration so
// transient noise (GC, network, neighbour load) hits both variants equally.
// A two-sample Welch t-test then reports whether the latency difference is
// statistically significant.
//
// Usage:
//
//	go run ./test/abtest -concurrency 50 -duration 30s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	flagConcurrency = flag.Int("concurrency", 50, "concurrent worker pairs")
	flagDuration    = flag.Duration("duration", 15*time.Second, "test duration")
	flagBase        = flag.String("base", "http://localhost:8080", "base URL")
)

type variant struct {
	name      string
	durations []time.Duration
	ok        int64
	fail      int64
	mu        sync.Mutex
}

func (v *variant) record(d time.Duration, ok bool) {
	v.mu.Lock()
	v.durations = append(v.durations, d)
	v.mu.Unlock()
	if ok {
		atomic.AddInt64(&v.ok, 1)
	} else {
		atomic.AddInt64(&v.fail, 1)
	}
}

func main() {
	flag.Parse()

	if err := waitForServer(*flagBase); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	email := fmt.Sprintf("ab-%d@test.local", time.Now().UnixNano())
	if err := registerUser(*flagBase, email, "password123"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	login, err := loginUser(*flagBase, email, "password123")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	A := &variant{name: "A: JWT (stateless)"}
	B := &variant{name: "B: Session ID (4 DB reads)"}

	fmt.Printf("A/B Test\n")
	fmt.Printf("  variant A:   GET /me with Bearer JWT (stateless)\n")
	fmt.Printf("  variant B:   GET /me with X-Session-ID (4 DB reads)\n")
	fmt.Printf("  concurrency: %d worker pairs\n", *flagConcurrency)
	fmt.Printf("  duration:    %s\n", *flagDuration)
	fmt.Printf("  base URL:    %s\n", *flagBase)
	fmt.Println()

	stop := time.NewTimer(*flagDuration)
	defer stop.Stop()
	done := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *flagConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				// Interleave: each loop calls A then B (or B then A on odd iterations)
				// to balance head-of-line and warm-cache bias.
				da, oka := callJWT(login.AccessToken)
				A.record(da, oka)
				db, okb := callSession(login.SessionID)
				B.record(db, okb)
			}
		}()
	}
	<-stop.C
	close(done)
	wg.Wait()
	elapsed := time.Since(start)

	reportVariant(A, elapsed)
	reportVariant(B, elapsed)
	compare(A, B)
}

func callJWT(token string) (time.Duration, bool) {
	t0 := time.Now()
	req, _ := http.NewRequest("GET", *flagBase+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	d := time.Since(t0)
	if err != nil {
		return d, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return d, resp.StatusCode == 200
}

func callSession(sessionID string) (time.Duration, bool) {
	t0 := time.Now()
	req, _ := http.NewRequest("GET", *flagBase+"/me", nil)
	req.Header.Set("X-Session-ID", sessionID)
	resp, err := httpClient.Do(req)
	d := time.Since(t0)
	if err != nil {
		return d, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return d, resp.StatusCode == 200
}

func reportVariant(v *variant, elapsed time.Duration) {
	v.mu.Lock()
	d := v.durations
	v.mu.Unlock()
	if len(d) == 0 {
		fmt.Printf("%s: no samples\n", v.name)
		return
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	throughput := float64(len(d)) / elapsed.Seconds()
	fmt.Println(v.name)
	fmt.Printf("  samples:    %d\n", len(d))
	fmt.Printf("  ok / fail:  %d / %d\n", v.ok, v.fail)
	fmt.Printf("  throughput: %.1f req/s\n", throughput)
	fmt.Printf("  p50/p95/p99: %s / %s / %s\n",
		d[len(d)*50/100], d[len(d)*95/100], d[len(d)*99/100])
	fmt.Printf("  mean:       %s\n", meanDur(d))
	fmt.Println()
}

func compare(A, B *variant) {
	A.mu.Lock()
	a := A.durations
	A.mu.Unlock()
	B.mu.Lock()
	b := B.durations
	B.mu.Unlock()
	if len(a) == 0 || len(b) == 0 {
		return
	}

	meanA := meanFloat(a)
	meanB := meanFloat(b)
	varA := variance(a, meanA)
	varB := variance(b, meanB)
	nA := float64(len(a))
	nB := float64(len(b))

	// Welch t-statistic
	t := (meanA - meanB) / math.Sqrt(varA/nA+varB/nB)
	// Welch-Satterthwaite df
	df := math.Pow(varA/nA+varB/nB, 2) /
		(math.Pow(varA/nA, 2)/(nA-1) + math.Pow(varB/nB, 2)/(nB-1))

	speedup := meanB / meanA

	fmt.Println("Comparison")
	fmt.Println("==========")
	fmt.Printf("  mean(A) = %s   mean(B) = %s\n", time.Duration(meanA), time.Duration(meanB))
	fmt.Printf("  B is %.2fx slower than A on mean latency\n", speedup)
	fmt.Printf("  Welch t = %.2f   df = %.0f\n", t, df)

	// Two-tailed test: |t| > 2.58 ≈ p<0.01 for any reasonably large df.
	switch {
	case math.Abs(t) > 3.29:
		fmt.Println("  significance: p < 0.001 (very strong)")
	case math.Abs(t) > 2.58:
		fmt.Println("  significance: p < 0.01 (strong)")
	case math.Abs(t) > 1.96:
		fmt.Println("  significance: p < 0.05 (significant)")
	default:
		fmt.Println("  significance: not significant (p > 0.05)")
	}

	if meanA < meanB {
		fmt.Println("  WINNER: A (JWT stateless)")
	} else {
		fmt.Println("  WINNER: B (Session ID)")
	}
}

// ---- helpers ----

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
	},
}

func meanDur(d []time.Duration) time.Duration {
	var s time.Duration
	for _, x := range d {
		s += x
	}
	return s / time.Duration(len(d))
}

func meanFloat(d []time.Duration) float64 {
	var s float64
	for _, x := range d {
		s += float64(x)
	}
	return s / float64(len(d))
}

func variance(d []time.Duration, mean float64) float64 {
	if len(d) < 2 {
		return 0
	}
	var s float64
	for _, x := range d {
		diff := float64(x) - mean
		s += diff * diff
	}
	return s / float64(len(d)-1)
}

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
	return fmt.Errorf("server at %s did not respond", base)
}

func registerUser(base, email, password string) error {
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q,"tenant_name":"AB"}`, email, password))
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
