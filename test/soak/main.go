// Soak test: run a steady workload for a long time and report per-minute
// latency + memory-growth indicators. The goal is to catch slow degradation
// (memory leaks, connection pool exhaustion, FD leaks) that short stress
// tests miss.
//
// Output: a per-bucket line every reporting interval plus a final summary.
//
// Usage:
//   go run ./test/soak -duration 10m -concurrency 20 -bucket 30s
//   go run ./test/soak -duration 1h  -concurrency 50 -bucket 1m -sla-drift-pct 50
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	flagDuration    = flag.Duration("duration", 5*time.Minute, "total soak duration")
	flagBucket      = flag.Duration("bucket", 30*time.Second, "reporting bucket size")
	flagConcurrency = flag.Int("concurrency", 20, "concurrent workers")
	flagBase        = flag.String("base", "http://localhost:8080", "base URL")
	flagSLADriftPct = flag.Float64("sla-drift-pct", 0, "fail if last-bucket p99 > first-bucket p99 by more than this %")
)

type sample struct {
	dur time.Duration
	ok  bool
}

type bucket struct {
	start     time.Time
	samples   []time.Duration
	ok, fail  int
	allocMB   float64 // process heap at end of bucket
}

func main() {
	flag.Parse()

	if err := waitForServer(*flagBase); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	email := fmt.Sprintf("soak-%d@test.local", time.Now().UnixNano())
	if err := registerUser(*flagBase, email, "password123"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	tok, err := loginUser(*flagBase, email, "password123")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Soak test\n")
	fmt.Printf("  duration:    %s\n", *flagDuration)
	fmt.Printf("  concurrency: %d\n", *flagConcurrency)
	fmt.Printf("  bucket:      %s\n", *flagBucket)
	fmt.Printf("  base URL:    %s\n", *flagBase)
	fmt.Println()
	fmt.Printf("%-9s %-9s %-9s %-9s %-9s %-7s %-9s\n", "elapsed", "count", "p50", "p95", "p99", "fail%", "heap")
	fmt.Println(strings.Repeat("-", 70))

	samples := make(chan sample, 4096)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < *flagConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				t0 := time.Now()
				req, _ := http.NewRequest("GET", *flagBase+"/me", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				resp, err := httpClient.Do(req)
				d := time.Since(t0)
				if err != nil {
					samples <- sample{d, false}
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				samples <- sample{d, resp.StatusCode == 200}
			}
		}()
	}

	end := time.Now().Add(*flagDuration)
	var buckets []*bucket
	current := &bucket{start: time.Now()}
	buckets = append(buckets, current)

	var totalOK, totalFail int64
	tick := time.NewTicker(*flagBucket)
	defer tick.Stop()
	stopAt := time.NewTimer(*flagDuration)
	defer stopAt.Stop()

drain:
	for {
		select {
		case s := <-samples:
			current.samples = append(current.samples, s.dur)
			if s.ok {
				current.ok++
				atomic.AddInt64(&totalOK, 1)
			} else {
				current.fail++
				atomic.AddInt64(&totalFail, 1)
			}
		case <-tick.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			current.allocMB = float64(m.HeapAlloc) / 1024 / 1024
			elapsed := time.Since(buckets[0].start).Round(time.Second)
			printBucket(elapsed, current)
			if time.Now().After(end) {
				break drain
			}
			current = &bucket{start: time.Now()}
			buckets = append(buckets, current)
		case <-stopAt.C:
			break drain
		}
	}
	close(stop)
	wg.Wait()

	// Drain remaining samples without blocking forever.
	for {
		select {
		case s := <-samples:
			current.samples = append(current.samples, s.dur)
			if s.ok {
				current.ok++
			} else {
				current.fail++
			}
		default:
			goto done
		}
	}
done:

	fmt.Println()
	fmt.Println("Summary")
	fmt.Printf("  total ok:   %d\n", totalOK)
	fmt.Printf("  total fail: %d\n", totalFail)

	// Drift analysis
	if len(buckets) >= 2 {
		first := pct(buckets[0].samples, 0.99)
		last := pct(buckets[len(buckets)-1].samples, 0.99)
		if first > 0 {
			drift := (float64(last)/float64(first) - 1) * 100
			fmt.Printf("  p99 drift:  first=%s last=%s (%+.1f%%)\n", first, last, drift)
			if *flagSLADriftPct > 0 && drift > *flagSLADriftPct {
				fmt.Printf("\nDRIFT SLA BREACH: p99 drifted %.1f%% > budget %.1f%%\n", drift, *flagSLADriftPct)
				os.Exit(2)
			}
		}
	}
}

func printBucket(elapsed time.Duration, b *bucket) {
	if len(b.samples) == 0 {
		fmt.Printf("%-9s (no samples)\n", elapsed)
		return
	}
	failPct := float64(b.fail) / float64(b.ok+b.fail) * 100
	fmt.Printf("%-9s %-9d %-9s %-9s %-9s %-7.2f %.1fMB\n",
		elapsed, len(b.samples),
		pct(b.samples, 0.50), pct(b.samples, 0.95), pct(b.samples, 0.99),
		failPct, b.allocMB,
	)
}

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted))*p) - 1
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

// ---- shared helpers ----

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 500,
		IdleConnTimeout:     90 * time.Second,
	},
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
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q,"tenant_name":"Soak"}`, email, password))
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
