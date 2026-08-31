// Package filesystem provides bounded file operations beneath configured named roots.
package filesystem

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	ErrUnknownRoot   = errors.New("unknown filesystem root")
	ErrInvalidPath   = errors.New("path must be relative and remain within its root")
	ErrSymlinkEscape = errors.New("path follows a symbolic link outside its root")
	ErrLimitExceeded = errors.New("operation exceeds configured limit")
	ErrReadOnly      = errors.New("filesystem root is read-only")
)

type Root struct {
	Path     string
	ReadOnly bool
}

type Options struct {
	MaxReadBytes int64
	MaxEntries   int
	MaxDiffBytes int64
}

type Service struct {
	roots map[string]resolvedRoot
	opts  Options
}

type resolvedRoot struct {
	path     string
	readOnly bool
}

type Entry struct {
	Name    string      `json:"name"`
	Path    string      `json:"path"`
	Size    int64       `json:"size"`
	Mode    fs.FileMode `json:"mode"`
	ModTime time.Time   `json:"modTime"`
	Type    string      `json:"type"`
}

type ReadResult struct {
	Data       []byte `json:"data"`
	Offset     int64  `json:"offset"`
	Truncated  bool   `json:"truncated"`
	NextOffset int64  `json:"nextOffset,omitempty"`
}

type StatResult struct {
	Path    string      `json:"path"`
	Size    int64       `json:"size"`
	Mode    fs.FileMode `json:"mode"`
	ModTime time.Time   `json:"modTime"`
	Type    string      `json:"type"`
}

func New(roots map[string]Root, opts Options) (*Service, error) {
	if opts.MaxReadBytes <= 0 {
		opts.MaxReadBytes = 1 << 20
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 1000
	}
	if opts.MaxDiffBytes <= 0 {
		opts.MaxDiffBytes = 1 << 20
	}
	s := &Service{roots: make(map[string]resolvedRoot, len(roots)), opts: opts}
	for name, root := range roots {
		if strings.TrimSpace(name) == "" || root.Path == "" {
			return nil, fmt.Errorf("invalid root %q", name)
		}
		absolute, err := filepath.Abs(root.Path)
		if err != nil {
			return nil, fmt.Errorf("root %q: %w", name, err)
		}
		canonical, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("root %q: %w", name, err)
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.IsDir() {
			if err == nil {
				err = errors.New("not a directory")
			}
			return nil, fmt.Errorf("root %q: %w", name, err)
		}
		s.roots[name] = resolvedRoot{path: filepath.Clean(canonical), readOnly: root.ReadOnly}
	}
	return s, nil
}

// Resolve validates a relative path and resolves all existing symlinks. For a
// target that does not exist, the nearest existing parent is resolved instead.
func (s *Service) Resolve(rootName, relative string, write bool) (string, error) {
	root, ok := s.roots[rootName]
	if !ok {
		return "", ErrUnknownRoot
	}
	if write && root.readOnly {
		return "", ErrReadOnly
	}
	if relative == "" {
		relative = "."
	}
	if filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" {
		return "", ErrInvalidPath
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrInvalidPath
	}
	candidate := filepath.Join(root.path, clean)
	if !within(root.path, candidate) {
		return "", ErrInvalidPath
	}
	probe := candidate
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			if !within(root.path, resolved) {
				return "", ErrSymlinkEscape
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			if !within(root.path, resolved) {
				return "", ErrSymlinkEscape
			}
			return resolved, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(probe)
		if parent == probe || !within(root.path, parent) {
			return "", ErrInvalidPath
		}
		suffix = append(suffix, filepath.Base(probe))
		probe = parent
	}
}

func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (s *Service) List(rootName, relative string, limit int) ([]Entry, error) {
	path, err := s.Resolve(rootName, relative, false)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > s.opts.MaxEntries {
		limit = s.opts.MaxEntries
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	items, err := dir.ReadDir(limit + 1)
	if err != nil {
		return nil, err
	}
	if len(items) > limit {
		return nil, fmt.Errorf("%w: directory contains more than %d entries", ErrLimitExceeded, limit)
	}
	result := make([]Entry, 0, len(items))
	for _, item := range items {
		info, err := item.Info()
		if err != nil {
			return nil, err
		}
		result = append(result, Entry{Name: item.Name(), Path: filepath.ToSlash(filepath.Join(relative, item.Name())), Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime(), Type: fileType(info.Mode())})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (s *Service) Read(rootName, relative string, offset, maxBytes int64) (ReadResult, error) {
	path, err := s.Resolve(rootName, relative, false)
	if err != nil {
		return ReadResult{}, err
	}
	if offset < 0 {
		return ReadResult{}, errors.New("offset must not be negative")
	}
	if maxBytes <= 0 {
		maxBytes = s.opts.MaxReadBytes
	}
	if maxBytes > s.opts.MaxReadBytes {
		return ReadResult{}, ErrLimitExceeded
	}
	f, err := os.Open(path)
	if err != nil {
		return ReadResult{}, err
	}
	defer f.Close()
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return ReadResult{}, err
	}
	b := make([]byte, maxBytes+1)
	n, readErr := io.ReadFull(f, b)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return ReadResult{}, readErr
	}
	truncated := int64(n) > maxBytes
	if truncated {
		n = int(maxBytes)
	}
	res := ReadResult{Data: b[:n], Offset: offset, Truncated: truncated}
	if truncated {
		res.NextOffset = offset + int64(n)
	}
	return res, nil
}

func (s *Service) Exists(rootName, relative string) (bool, error) {
	path, err := s.Resolve(rootName, relative, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	_, err = os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) Stat(rootName, relative string) (StatResult, error) {
	path, err := s.Resolve(rootName, relative, false)
	if err != nil {
		return StatResult{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return StatResult{}, err
	}
	return StatResult{Path: filepath.ToSlash(relative), Size: info.Size(), Mode: info.Mode(), ModTime: info.ModTime(), Type: fileType(info.Mode())}, nil
}

func fileType(mode fs.FileMode) string {
	switch {
	case mode.IsRegular():
		return "file"
	case mode.IsDir():
		return "directory"
	case mode&fs.ModeSymlink != 0:
		return "symlink"
	default:
		return "other"
	}
}

func (s *Service) Diff(rootName, relative string, proposed []byte) (string, error) {
	if int64(len(proposed)) > s.opts.MaxDiffBytes {
		return "", ErrLimitExceeded
	}
	current, err := s.Read(rootName, relative, 0, s.opts.MaxDiffBytes)
	if err != nil {
		return "", err
	}
	if current.Truncated {
		return "", ErrLimitExceeded
	}
	return UnifiedDiff(current.Data, proposed, "current/"+relative, "proposed/"+relative), nil
}

func (s *Service) WriteAtomic(rootName, relative string, data []byte, mode fs.FileMode) error {
	if int64(len(data)) > s.opts.MaxDiffBytes {
		return ErrLimitExceeded
	}
	path, err := s.Resolve(rootName, relative, true)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if info, statErr := os.Stat(parent); statErr != nil || !info.IsDir() {
		if statErr != nil {
			return statErr
		}
		return errors.New("parent is not a directory")
	}
	if existing, statErr := os.Stat(path); statErr == nil && mode == 0 {
		mode = existing.Mode().Perm()
	}
	if mode == 0 {
		mode = 0o600
	}
	temp, err := os.CreateTemp(parent, ".remoteops-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err = temp.Chmod(mode.Perm()); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tempName, path); err != nil {
		return err
	}
	if d, openErr := os.Open(parent); openErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func Hash(data []byte) string { sum := sha256.Sum256(data); return fmt.Sprintf("%x", sum) }

// UnifiedDiff returns a compact line-oriented diff. It intentionally bounds
// complexity by showing a complete replacement rather than computing an LCS.
func UnifiedDiff(before, after []byte, beforeName, afterName string) string {
	if bytes.Equal(before, after) {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s\n", beforeName, afterName)
	oldLines := splitLines(before)
	newLines := splitLines(after)
	fmt.Fprintf(&b, "@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines))
	for _, line := range oldLines {
		b.WriteByte('-')
		b.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			b.WriteByte('\n')
		}
	}
	for _, line := range newLines {
		b.WriteByte('+')
		b.WriteString(line)
		if !strings.HasSuffix(line, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	parts := strings.SplitAfter(string(data), "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}
