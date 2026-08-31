// Package audit writes append-only, secret-redacted JSONL security records.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

const replacement = "[REDACTED]"

type Event struct {
	Timestamp  time.Time               `json:"timestamp,omitempty"`
	RequestID  string                  `json:"requestId,omitempty"`
	Actor      string                  `json:"actor,omitempty"`
	Action     string                  `json:"action"`
	Class      permissions.ActionClass `json:"class"`
	Target     string                  `json:"target,omitempty"`
	Allowed    bool                    `json:"allowed"`
	Success    bool                    `json:"success"`
	DurationMS int64                   `json:"durationMs,omitempty"`
	Error      string                  `json:"error,omitempty"`
	ChangeID   string                  `json:"changeId,omitempty"`
	GodMode    bool                    `json:"godMode"`
	Details    map[string]any          `json:"details,omitempty"`
}

type Recorder interface {
	Record(ctx context.Context, event Event) error
}

type Options struct {
	SecretValues []string
	Now          func() time.Time
	SyncWrites   bool
}

type Service struct {
	mu         sync.Mutex
	writer     io.Writer
	closer     io.Closer
	redactor   Redactor
	now        func() time.Time
	syncWrites bool
}

func New(path string, options Options) (*Service, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("audit path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure audit log permissions: %w", err)
	}
	service := NewWriter(file, options)
	service.closer = file
	return service, nil
}

func NewWriter(writer io.Writer, options Options) *Service {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		writer: writer, redactor: NewRedactor(options.SecretValues), now: now,
		syncWrites: options.SyncWrites,
	}
}

func (s *Service) Record(_ context.Context, event Event) error {
	if s == nil || s.writer == nil {
		return errors.New("audit service is not configured")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = s.now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	event = s.redactEvent(event)
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.writer.Write(line); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	if s.syncWrites {
		if syncer, ok := s.writer.(interface{ Sync() error }); ok {
			if err := syncer.Sync(); err != nil {
				return fmt.Errorf("sync audit event: %w", err)
			}
		}
	}
	return nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closer == nil {
		return nil
	}
	err := s.closer.Close()
	s.closer = nil
	return err
}

func (s *Service) redactEvent(event Event) Event {
	event.RequestID = s.redactor.String(event.RequestID)
	event.Actor = s.redactor.String(event.Actor)
	event.Action = s.redactor.String(event.Action)
	event.Target = s.redactor.String(event.Target)
	event.Error = s.redactor.String(event.Error)
	event.ChangeID = s.redactor.String(event.ChangeID)
	if event.Details != nil {
		event.Details = s.redactor.Map(event.Details)
	}
	return event
}

type Redactor struct {
	secrets  []string
	patterns []*regexp.Regexp
}

func NewRedactor(secretValues []string) Redactor {
	secrets := make([]string, 0, len(secretValues))
	for _, value := range secretValues {
		if value != "" {
			secrets = append(secrets, value)
		}
	}
	return Redactor{
		secrets: secrets,
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bBearer\s+[^\s,;]+`),
			regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)`),
			regexp.MustCompile(`(?i)(--(?:password|secret|token|api[_-]?key))(\s+)([^\s]+)`),
			regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^:/\s]+:)([^@/\s]+)(@)`),
		},
	}
}

func (r Redactor) String(value string) string {
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, replacement)
	}
	value = r.patterns[0].ReplaceAllString(value, "Bearer "+replacement)
	value = r.patterns[1].ReplaceAllString(value, "$1$2"+replacement)
	value = r.patterns[2].ReplaceAllString(value, "$1$2"+replacement)
	value = r.patterns[3].ReplaceAllString(value, "$1"+replacement+"$3")
	return value
}

func (r Redactor) Map(input map[string]any) map[string]any {
	redacted := make(map[string]any, len(input))
	for key, value := range input {
		if sensitiveKey(key) {
			redacted[key] = replacement
			continue
		}
		redacted[key] = r.Value(value)
	}
	return redacted
}

func (r Redactor) Value(value any) any {
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case string:
		return r.String(typed)
	case error:
		return r.String(typed.Error())
	case map[string]any:
		return r.Map(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = r.Value(item)
		}
		return result
	}

	// Detail values commonly arrive as typed maps/slices. Normalize them through
	// JSON so key-based redaction is applied without retaining mutable aliases.
	kind := reflect.TypeOf(value).Kind()
	if kind == reflect.Map || kind == reflect.Slice || kind == reflect.Array || kind == reflect.Struct || kind == reflect.Pointer {
		encoded, err := json.Marshal(value)
		if err == nil {
			var normalized any
			if json.Unmarshal(encoded, &normalized) == nil {
				return r.Value(normalized)
			}
		}
	}
	return value
}

func sensitiveKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_"))
	for _, marker := range []string{"password", "passwd", "secret", "token", "api_key", "apikey", "authorization", "credential", "private_key"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}
