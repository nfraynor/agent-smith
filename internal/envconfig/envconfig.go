// Package envconfig edits dotenv files without reserializing unrelated lines.
package envconfig

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nfraynor/agent-smith/internal/filesystem"
)

var ErrKeyNotFound = errors.New("environment key not found")

const RedactedValue = "[REDACTED]"

var assignmentPattern = regexp.MustCompile(`^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*?)(\r?\n)?$`)
var validKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Service struct {
	files          *filesystem.Service
	maxBytes       int64
	secretPatterns []string
}

type Variable struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret bool   `json:"secret"`
}

func New(files *filesystem.Service, maxBytes int64, secretPatterns []string) *Service {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if len(secretPatterns) == 0 {
		secretPatterns = []string{"PASSWORD", "SECRET", "TOKEN", "API_KEY"}
	}
	patterns := make([]string, 0, len(secretPatterns))
	for _, p := range secretPatterns {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, strings.ToUpper(p))
		}
	}
	return &Service{files: files, maxBytes: maxBytes, secretPatterns: patterns}
}

func (s *Service) Get(root, file, key string, revealSecrets bool) (Variable, error) {
	if !validKey.MatchString(key) {
		return Variable{}, fmt.Errorf("invalid environment key %q", key)
	}
	lines, _, err := s.load(root, file)
	if err != nil {
		return Variable{}, err
	}
	var found *line
	for i := range lines {
		if lines[i].key == key {
			found = &lines[i]
		}
	}
	if found == nil {
		return Variable{}, ErrKeyNotFound
	}
	secret := s.isSecret(key)
	value := found.value
	if secret && !revealSecrets {
		value = RedactedValue
	}
	return Variable{Key: key, Value: value, Secret: secret}, nil
}

func (s *Service) List(root, file string, revealSecrets bool) ([]Variable, error) {
	lines, _, err := s.load(root, file)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	order := []string{}
	for _, line := range lines {
		if line.key == "" {
			continue
		}
		if _, ok := values[line.key]; !ok {
			order = append(order, line.key)
		}
		values[line.key] = line.value
	}
	result := make([]Variable, 0, len(values))
	for _, key := range order {
		secret := s.isSecret(key)
		value := values[key]
		if secret && !revealSecrets {
			value = RedactedValue
		}
		result = append(result, Variable{Key: key, Value: value, Secret: secret})
	}
	return result, nil
}

func (s *Service) Set(root, file, key, value string) error {
	if !validKey.MatchString(key) {
		return fmt.Errorf("invalid environment key %q", key)
	}
	lines, original, err := s.load(root, file)
	if err != nil {
		return err
	}
	last := -1
	for i := range lines {
		if lines[i].key == key {
			last = i
		}
	}
	encoded := quote(value)
	if last >= 0 {
		l := lines[last]
		lines[last].raw = l.prefix + encoded + l.comment + l.newline
	} else {
		if len(original) > 0 && !strings.HasSuffix(string(original), "\n") {
			lines = append(lines, line{raw: "\n"})
		}
		lines = append(lines, line{raw: key + "=" + encoded + "\n", key: key, value: value})
	}
	return s.write(root, file, lines)
}

func (s *Service) Delete(root, file, key string) error {
	if !validKey.MatchString(key) {
		return fmt.Errorf("invalid environment key %q", key)
	}
	lines, _, err := s.load(root, file)
	if err != nil {
		return err
	}
	filtered := make([]line, 0, len(lines))
	found := false
	for _, l := range lines {
		if l.key == key {
			found = true
			continue
		}
		filtered = append(filtered, l)
	}
	if !found {
		return ErrKeyNotFound
	}
	return s.write(root, file, filtered)
}

func (s *Service) isSecret(key string) bool {
	upper := strings.ToUpper(key)
	for _, p := range s.secretPatterns {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

type line struct{ raw, key, value, prefix, comment, newline string }

func (s *Service) load(root, file string) ([]line, []byte, error) {
	read, err := s.files.Read(root, file, 0, s.maxBytes)
	if err != nil {
		return nil, nil, err
	}
	if read.Truncated {
		return nil, nil, filesystem.ErrLimitExceeded
	}
	rawLines := splitKeepNewline(string(read.Data))
	result := make([]line, 0, len(rawLines))
	for _, raw := range rawLines {
		l := line{raw: raw}
		m := assignmentPattern.FindStringSubmatch(raw)
		if m != nil {
			l.key = m[2]
			l.prefix = m[1] + m[2] + m[3]
			l.newline = m[5]
			body := m[4]
			valuePart, comment := splitComment(body)
			l.comment = comment
			l.value = parseValue(strings.TrimSpace(valuePart))
		}
		result = append(result, l)
	}
	return result, read.Data, nil
}

func (s *Service) write(root, file string, lines []line) error {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.raw)
	}
	return s.files.WriteAtomic(root, file, []byte(b.String()), 0)
}

func splitKeepNewline(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.SplitAfter(value, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func splitComment(value string) (string, string) {
	quote := byte(0)
	escaped := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '#' && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
			start := i
			for start > 0 && (value[start-1] == ' ' || value[start-1] == '\t') {
				start--
			}
			return value[:start], value[start:]
		}
	}
	return value, ""
}

func parseValue(value string) string {
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1]
	}
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		if decoded, err := strconv.Unquote(value); err == nil {
			return decoded
		}
	}
	return value
}

func quote(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\r\n#'\"\\$") {
		return value
	}
	return strconv.Quote(value)
}

// Keys returns sorted keys without exposing values; useful for diagnostics.
func (s *Service) Keys(root, file string) ([]string, error) {
	vars, err := s.List(root, file, false)
	if err != nil {
		return nil, err
	}
	keys := make([]string, len(vars))
	for i, v := range vars {
		keys[i] = v.Key
	}
	sort.Strings(keys)
	return keys, nil
}
