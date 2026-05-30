// Spike test: warm at a steady baseline, then 10× burst, measure recovery.
// Reports baseline / burst / recovery latency and confirms no failures during
// the spike.
//
// Usage:
//   go run ./test/spike -baseline 10 -burst 100 -burst-duration 5s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	flagBaseline      = flag.Int("baseline", 10, "baseline concurrent workers")
	flagBurst         = flag.Int("burst", 100, "burst concurrent workers (added on top)")
	flagBaselineDur   = flag.Duration("baseline-duration", 5*time.Second, "baseline duration before burst")
	flagBurstDur      = flag.Duration("burst-duration", 5*time.Second, "burst duration")
	flagRecoveryDur   = flag.Duration("recovery-duration", 10*time.Second, "post-burst observation")
	flagBase          = flag.String("base", "http://localhost:8080", "base URL")
	flagSLABurstFail  = flag.Float64("sla-burst-fail-pct", 5.0, "fail if burst-phase failure rate > this %")
	flagSLARecoveryMs = flag.Duration("sla-recovery-p99", 0, "fail if recovery-phase p99 > this")
)

type phase struct {
	name      string
	durations []time.Duration
	ok, fail  int64
	mu        sync.Mutex
}

func (p *phase) record(d time.Duration, ok bool) {
	p.mu.Lock()
	p.durations = append(p.durations, d)
	p.mu.Unlock()
	if ok {
		atomic.AddInt64(&p.ok, 1)
	} else {
		atomic.AddInt64(&p.fail, 1)
	}
}

var (
	currentPhase atomic.Pointer[phase]
)

func main() {
	flag.Parse()

	if err := waitForServer(*flagBase); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	email := fmt.Sprintf("spike-%d@test.local", time.Now().UnixNano())
	if err := registerUser(*flagBase, email, "password123"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	token, err := loginUser(*flagBase, email, "password123")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	pBaseline := &phase{name: "baseline"}
	pBurst := &phase{name: "burst"}
	pRecovery := &phase{name: "recovery"}

	fmt.Printf("Spike test\n")
	fmt.Printf("  baseline:  %d workers for %s\n", *flagBaseline, *flagBaselineDur)
	fmt.Printf("  burst:     +%d workers for %s\n", *flagBurst, *flagBurstDur)
	fmt.Printf("  recovery:  %d workers for %s\n", *flagBaseline, *flagRecoveryDur)
	fmt.Println()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Start baseline workers (run through the entire test).
	currentPhase.Store(pBaseline)
	for i := 0; i < *flagBaseline; i++ {
		wg.Add(1)
		go worker(&wg, stop, token)
	}
	time.Sleep(*flagBaselineDur)

	// Switch to burst phase and add workers.
	currentPhase.Store(pBurst)
	burstStop := make(chan struct{})
	for i := 0; i < *flagBurst; i++ {
		wg.Add(1)
		go worker(&wg, burstStop, token)
	}
	time.Sleep(*flagBurstDur)

	// Kill burst workers, switch to recovery.
	close(burstStop)
	currentPhase.Store(pRecovery)
	time.Sleep(*flagRecoveryDur)

	close(stop)
	wg.Wait()

	report(pBaseline)
	report(pBurst)
	report(pRecovery)

	// SLA checks
	breaches := []string{}
	if pBurst.ok+pBurst.fail > 0 {
		burstFailPct := float64(pBurst.fail) / float64(pBurst.ok+pBurst.fail) * 100
		if burstFailPct > *flagSLABurstFail {
			breaches = append(breaches, fmt.Sprintf("burst failure rate %.2f%% > budget %.2f%%", burstFailPct, *flagSLABurstFail))
		}
	}
	if *flagSLARecoveryMs > 0 && len(pRecovery.durations) > 0 {
		p99 := pctOf(pRecovery.durations, 0.99)
		if p99 > *flagSLARecoveryMs {
			breaches = append(breaches, fmt.Sprintf("recovery p99 %s > budget %s", p99, *flagSLARecoveryMs))
		}
	}
	if len(breaches) > 0 {
		fmt.Println("\nSPIKE SLA BREACH")
		for _, b := range breaches {
			fmt.Printf("  - %s\n", b)
		}
		os.Exit(2)
	}
}

func worker(wg *sync.WaitGroup, stop chan struct{}, token string) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		t0 := time.Now()
		req, _ := http.NewRequest("GET", *flagBase+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := httpClient.Do(req)
		d := time.Since(t0)
		p := currentPhase.Load()
		if err != nil {
			p.record(d, false)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		p.record(d, resp.StatusCode == 200)
	}
}

func report(p *phase) {
	p.mu.Lock()
	d := p.durations
	p.mu.Unlock()
	if len(d) == 0 {
		fmt.Printf("%-10s (no samples)\n", p.name)
		return
	}
	failPct := float64(p.fail) / float64(p.ok+p.fail) * 100
	fmt.Printf("%-10s n=%-6d p50=%-9s p95=%-9s p99=%-9s max=%-9s fail=%.2f%%\n",
		p.name, len(d),
		pctOf(d, 0.50), pctOf(d, 0.95), pctOf(d, 0.99), pctOf(d, 1.0), failPct)
}

func pctOf(d []time.Duration, p float64) time.Duration {
	sorted := append([]time.Duration(nil), d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted))*p) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---- shared ----

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{MaxIdleConns: 500, MaxIdleConnsPerHost: 500},
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
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q,"tenant_name":"Spike"}`, email, password))
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

func loginUser(base, email, password string) (string, error) {
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	resp, err := http.Post(base+"/login", "application/json", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login status %d", resp.StatusCode)
	}
	var li struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&li); err != nil {
		return "", err
	}
	return li.AccessToken, nil
}
