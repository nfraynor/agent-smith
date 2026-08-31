package limits

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLimiterSeparatesClientsAndBudgets(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	limiter := newLimiter(3, 1, func() time.Time { return now })
	if !limiter.Allow("actor-a", true) || limiter.Allow("actor-a", true) {
		t.Fatal("mutation budget was not enforced")
	}
	if !limiter.Allow("actor-a", false) || !limiter.Allow("actor-a", false) || limiter.Allow("actor-a", false) {
		t.Fatal("request budget was not enforced")
	}
	if !limiter.Allow("actor-b", true) {
		t.Fatal("one actor consumed another actor's budget")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("actor-a", true) {
		t.Fatal("budget did not reset after its window")
	}
}

func TestLimiterIsSafeUnderConcurrency(t *testing.T) {
	limiter := NewLimiter(100, 10)
	var group sync.WaitGroup
	allowed := make(chan bool, 50)
	for range 50 {
		group.Add(1)
		go func() { defer group.Done(); allowed <- limiter.Allow("one", true) }()
	}
	group.Wait()
	close(allowed)
	count := 0
	for value := range allowed {
		if value {
			count++
		}
	}
	if count != 10 {
		t.Fatalf("allowed %d mutations, want 10", count)
	}
}

func TestOutputBounds(t *testing.T) {
	stdout, stderr, truncated := BoundCombined([]byte("12345"), []byte("67890"), 7)
	if string(stdout) != "12345" || string(stderr) != "67" || !truncated {
		t.Fatalf("unexpected bound result %q %q %v", stdout, stderr, truncated)
	}
	var writer Writer
	writer.Maximum = 4
	if _, err := io.Copy(&writer, strings.NewReader("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	if writer.String() != "abcd" || !writer.Truncated() {
		t.Fatalf("writer = %q, truncated=%v", writer.String(), writer.Truncated())
	}
}

func TestExecutionTimeout(t *testing.T) {
	if got, err := ExecutionTimeout(time.Minute, 0); got != time.Minute || err != nil {
		t.Fatalf("default timeout = %v, %v", got, err)
	}
	if _, err := ExecutionTimeout(time.Minute, 2*time.Minute); err == nil {
		t.Fatal("expected excessive timeout to fail")
	}
}
