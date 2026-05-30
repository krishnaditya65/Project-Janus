// Package metrics exposes Prometheus instruments for the auth server.
//
// Goal: low-cardinality, high-signal metrics. We label by method + path
// template + status class. We do NOT label by tenant or user ID (that would
// blow the cardinality bound).
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	HTTPRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_http_requests_total",
			Help: "Total HTTP requests served, by method/route/status.",
		},
		[]string{"method", "route", "status"},
	)

	HTTPDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_http_request_duration_seconds",
			Help:    "End-to-end HTTP request latency.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "route", "status"},
	)

	AuthEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_events_total",
			Help: "Auth-domain events (login_success, login_fail, refresh, logout, mfa_required, mfa_complete).",
		},
		[]string{"event"},
	)

	PrincipalCacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "auth_principal_cache_hits_total",
		Help: "Principal-cache hits.",
	})
	PrincipalCacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "auth_principal_cache_misses_total",
		Help: "Principal-cache misses (fall-through to DB).",
	})
)

func init() {
	prometheus.MustRegister(
		HTTPRequests, HTTPDuration, AuthEvents,
		PrincipalCacheHits, PrincipalCacheMisses,
	)
}

// Handler returns the /metrics HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// statusRecorder lets us read the response status for the metrics middleware.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Middleware records http_requests_total + duration histogram. RouteFn
// extracts the route template from the request; pass `func(*http.Request) string`
// that returns e.g. "/users/{id}" rather than "/users/abc-123" to keep
// label cardinality bounded.
func Middleware(routeFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sr, r)

			route := "unknown"
			if routeFn != nil {
				if rt := routeFn(r); rt != "" {
					route = rt
				}
			}
			statusStr := strconv.Itoa(sr.status)
			HTTPRequests.WithLabelValues(r.Method, route, statusStr).Inc()
			HTTPDuration.WithLabelValues(r.Method, route, statusStr).Observe(time.Since(start).Seconds())
		})
	}
}
