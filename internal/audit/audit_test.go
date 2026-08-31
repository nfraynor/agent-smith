package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

func TestRecordWritesStructuredRedactedJSONL(t *testing.T) {
	var output bytes.Buffer
	fixed := time.Date(2026, 8, 31, 13, 18, 34, 0, time.FixedZone("offset", 2*60*60))
	service := NewWriter(&output, Options{SecretValues: []string{"literal-secret"}, Now: func() time.Time { return fixed }})
	err := service.Record(context.Background(), Event{
		Actor: "chatgpt", Action: "godmode_shell", Class: permissions.GodMode,
		Target: "https://user:password@example.test/path", Allowed: true, Success: false,
		Error:   "Authorization: Bearer bearer-value; literal-secret",
		GodMode: true,
		Details: map[string]any{
			"command": "deploy --token command-secret --password hunter2",
			"API_KEY": "key-secret",
			"nested":  map[string]any{"clientSecret": "nested-secret", "safe": "visible"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	line := output.String()
	for _, secret := range []string{"literal-secret", "bearer-value", "password@example", "command-secret", "hunter2", "key-secret", "nested-secret"} {
		if strings.Contains(line, secret) {
			t.Errorf("audit leaked %q: %s", secret, line)
		}
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if !event.Timestamp.Equal(fixed.UTC()) || event.Action != "godmode_shell" || event.Details["API_KEY"] != replacement {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestConcurrentRecordsRemainOneJSONObjectPerLine(t *testing.T) {
	var output lockedBuffer
	service := NewWriter(&output, Options{})
	var group sync.WaitGroup
	for range 50 {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := service.Record(context.Background(), Event{Action: "docker_list", Class: permissions.ReadOnly, Allowed: true, Success: true}); err != nil {
				t.Errorf("Record: %v", err)
			}
		}()
	}
	group.Wait()
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 50 {
		t.Fatalf("lines = %d", len(lines))
	}
	for _, line := range lines {
		var value map[string]any
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			t.Fatalf("invalid JSON line: %v", err)
		}
	}
}

func TestSensitiveKeyDetectionAvoidsCommonSecrets(t *testing.T) {
	redactor := NewRedactor(nil)
	result := redactor.Map(map[string]any{
		"access_token": "a", "dbPassword": "b", "credentialFile": "c", "safe": "d",
	})
	if result["access_token"] != replacement || result["dbPassword"] != replacement || result["credentialFile"] != replacement || result["safe"] != "d" {
		t.Fatalf("unexpected redaction: %#v", result)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(value)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
