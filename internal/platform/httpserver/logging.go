package httpserver

import (
	"log/slog"
	"net/http"
	"time"
)

// statusRecorder wraps ResponseWriter to capture the response status code
// and bytes written for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// RequestLogger emits a structured log line per request: method, path,
// status, duration, remote IP, user agent. Bytes written is included for
// outbound payload sizing.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w}

		next.ServeHTTP(sr, r)

		dur := time.Since(start)
		status := sr.status
		if status == 0 {
			status = http.StatusOK
		}

		level := slog.LevelInfo
		switch {
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		}

		slog.LogAttrs(r.Context(), level, "http_request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("dur", dur),
			slog.Int("bytes", sr.bytes),
			slog.String("remote", r.RemoteAddr),
			slog.String("ua", r.UserAgent()),
		)
	})
}
