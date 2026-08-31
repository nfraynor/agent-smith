// Package limits provides protocol resource bounds and per-client rate limits.
package limits

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

var ErrRateLimited = errors.New("rate limit exceeded")

type Limiter struct {
	mu        sync.Mutex
	requests  int
	mutations int
	window    time.Duration
	now       func() time.Time
	clients   map[string]counter
}

type counter struct {
	windowStart time.Time
	requests    int
	mutations   int
}

func NewLimiter(requestsPerMinute, mutationsPerMinute int) *Limiter {
	return newLimiter(requestsPerMinute, mutationsPerMinute, time.Now)
}

func newLimiter(requestsPerMinute, mutationsPerMinute int, now func() time.Time) *Limiter {
	return &Limiter{
		requests: requestsPerMinute, mutations: mutationsPerMinute,
		window: time.Minute, now: now, clients: make(map[string]counter),
	}
}

// Allow atomically applies both the total request budget and, for mutations,
// the tighter mutation budget. Rejected requests do not consume either budget.
func (l *Limiter) Allow(key string, mutation bool) bool {
	if l == nil || l.requests <= 0 || l.mutations <= 0 {
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	current := l.clients[key]
	if current.windowStart.IsZero() || !now.Before(current.windowStart.Add(l.window)) {
		current = counter{windowStart: now}
	}
	if current.requests >= l.requests || (mutation && current.mutations >= l.mutations) {
		l.clients[key] = current
		return false
	}
	current.requests++
	if mutation {
		current.mutations++
	}
	l.clients[key] = current
	return true
}

// Forget allows callers to release state for identities that will no longer be
// seen. Ordinary deployments can simply let the small per-identity map persist.
func (l *Limiter) Forget(key string) {
	l.mu.Lock()
	delete(l.clients, key)
	l.mu.Unlock()
}

func Truncate(content []byte, maximum int64) ([]byte, bool) {
	if maximum < 0 {
		maximum = 0
	}
	if int64(len(content)) <= maximum {
		return content, false
	}
	result := make([]byte, maximum)
	copy(result, content)
	return result, true
}

// BoundCombined applies one budget across stdout then stderr, matching the
// order in which these fields are returned in tool results.
func BoundCombined(stdout, stderr []byte, maximum int64) ([]byte, []byte, bool) {
	stdout, stdoutTruncated := Truncate(stdout, maximum)
	remaining := maximum - int64(len(stdout))
	stderr, stderrTruncated := Truncate(stderr, remaining)
	return stdout, stderr, stdoutTruncated || stderrTruncated
}

// Writer captures at most Maximum bytes while reporting successful writes to
// producers. This avoids unbounded buffers and avoids io.ErrShortWrite loops.
type Writer struct {
	Maximum   int64
	buffer    bytes.Buffer
	written   int64
	truncated bool
}

func (w *Writer) Write(content []byte) (int, error) {
	w.written += int64(len(content))
	remaining := w.Maximum - int64(w.buffer.Len())
	if remaining > 0 {
		keep := int64(len(content))
		if keep > remaining {
			keep = remaining
		}
		_, _ = w.buffer.Write(content[:keep])
	}
	if w.written > w.Maximum {
		w.truncated = true
	}
	return len(content), nil
}

func (w *Writer) Bytes() []byte   { return w.buffer.Bytes() }
func (w *Writer) String() string  { return w.buffer.String() }
func (w *Writer) Truncated() bool { return w.truncated }

func LimitReader(reader io.Reader, maximum int64) io.Reader {
	if maximum < 0 {
		maximum = 0
	}
	return io.LimitReader(reader, maximum)
}

func MaxRequestBytes(maximum int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, maximum)
		next.ServeHTTP(writer, request)
	})
}

func ExecutionTimeout(parent time.Duration, requested time.Duration) (time.Duration, error) {
	if parent <= 0 {
		return 0, errors.New("maximum execution timeout must be positive")
	}
	if requested <= 0 {
		return parent, nil
	}
	if requested > parent {
		return 0, errors.New("requested execution timeout exceeds the configured maximum")
	}
	return requested, nil
}
