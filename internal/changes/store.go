// Package changes persists file-backed change records and conflict-safe rollbacks.
package changes

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	managedfs "github.com/nfraynor/agent-smith/internal/filesystem"
)

var (
	ErrNotFound            = errors.New("change not found")
	ErrConflict            = errors.New("target has changed since the recorded change")
	ErrTooLarge            = errors.New("change target exceeds configured limit")
	ErrRollbackUnsupported = errors.New("rollback is not supported for this change")
)

var idPattern = regexp.MustCompile(`^chg_[0-9]{14}_[0-9a-f]{12}$`)

type Options struct {
	RetentionDays  int
	MaxRecords     int
	MaxTargetBytes int64
	Now            func() time.Time
	OnPrune        func(Change) error
}

type Store struct {
	dir         string
	opts        Options
	mu          sync.Mutex
	targetLocks map[string]*sync.Mutex
}

type Change struct {
	ID                string    `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	Actor             string    `json:"actor"`
	Operation         string    `json:"operation"`
	Target            string    `json:"target"`
	Description       string    `json:"description"`
	BeforeHash        string    `json:"beforeHash"`
	AfterHash         string    `json:"afterHash"`
	Backup            string    `json:"backup"`
	Status            string    `json:"status"`
	RollbackSupported bool      `json:"rollbackSupported"`
	RollbackOf        string    `json:"rollbackOf,omitempty"`
	Error             string    `json:"error,omitempty"`
}

type RecordInput struct {
	Actor, Operation, Target, Description string
	Before, After                         []byte
	External                              bool
}
type ListFilter struct {
	Since             time.Time
	Operation, Target string
	Limit             int
}

func New(dir string, opts Options) (*Store, error) {
	if dir == "" {
		return nil, errors.New("changes directory is required")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 10000
	}
	if opts.MaxTargetBytes <= 0 {
		opts.MaxTargetBytes = 8 << 20
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err = os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	if err = os.Chmod(absolute, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: absolute, opts: opts, targetLocks: map[string]*sync.Mutex{}}, nil
}

func (s *Store) Record(input RecordInput) (Change, error) {
	if int64(len(input.Before)) > s.opts.MaxTargetBytes || int64(len(input.After)) > s.opts.MaxTargetBytes {
		return Change{}, ErrTooLarge
	}
	if input.Operation == "" || input.Target == "" {
		return Change{}, errors.New("operation and target are required")
	}
	change := Change{Timestamp: s.opts.Now().UTC(), Actor: input.Actor, Operation: input.Operation, Target: input.Target, Description: input.Description, BeforeHash: hash(input.Before), AfterHash: hash(input.After), Status: "applied", RollbackSupported: !input.External}
	if err := s.persist(&change, input.Before, input.After); err != nil {
		return Change{}, err
	}
	_ = s.Prune()
	return change, nil
}

func (s *Store) persist(change *Change, before, after []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if change.ID == "" {
		id, err := s.newID(change.Timestamp)
		if err != nil {
			return err
		}
		change.ID = id
	}
	dir := filepath.Join(s.dir, change.ID)
	temp, err := os.MkdirTemp(s.dir, ".change-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	if err = os.Chmod(temp, 0o700); err != nil {
		return err
	}
	if err = writeFileSync(filepath.Join(temp, "before"), before, 0o600); err != nil {
		return err
	}
	if err = writeFileSync(filepath.Join(temp, "after"), after, 0o600); err != nil {
		return err
	}
	diff := managedfs.UnifiedDiff(before, after, "before", "after")
	if err = writeFileSync(filepath.Join(temp, "diff.patch"), []byte(diff), 0o600); err != nil {
		return err
	}
	change.Backup = filepath.Join(dir, "before")
	metadata, err := json.MarshalIndent(change, "", "  ")
	if err != nil {
		return err
	}
	metadata = append(metadata, '\n')
	if err = writeFileSync(filepath.Join(temp, "metadata.json"), metadata, 0o600); err != nil {
		return err
	}
	if err = os.Rename(temp, dir); err != nil {
		return err
	}
	return syncDir(s.dir)
}

func (s *Store) newID(timestamp time.Time) (string, error) {
	for i := 0; i < 10; i++ {
		random := make([]byte, 6)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		id := "chg_" + timestamp.Format("20060102150405") + "_" + hex.EncodeToString(random)
		if _, err := os.Stat(filepath.Join(s.dir, id)); errors.Is(err, fs.ErrNotExist) {
			return id, nil
		}
	}
	return "", errors.New("could not allocate unique change id")
}

func (s *Store) Get(id string) (Change, error) {
	if !idPattern.MatchString(id) {
		return Change{}, ErrNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.dir, id, "metadata.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return Change{}, ErrNotFound
	}
	if err != nil {
		return Change{}, err
	}
	var change Change
	if err = json.Unmarshal(data, &change); err != nil {
		return Change{}, fmt.Errorf("decode change %s: %w", id, err)
	}
	if change.ID != id {
		return Change{}, errors.New("change metadata id mismatch")
	}
	return change, nil
}

func (s *Store) Diff(id string) (string, error) {
	if _, err := s.Get(id); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(s.dir, id, "diff.patch"))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > s.opts.MaxTargetBytes*3 {
		return "", ErrTooLarge
	}
	return string(data), nil
}

func (s *Store) List(filter ListFilter) ([]Change, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	changes := make([]Change, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
			continue
		}
		change, err := s.Get(entry.Name())
		if err != nil {
			return nil, err
		}
		if !filter.Since.IsZero() && change.Timestamp.Before(filter.Since) {
			continue
		}
		if filter.Operation != "" && change.Operation != filter.Operation {
			continue
		}
		if filter.Target != "" && !strings.Contains(change.Target, filter.Target) {
			continue
		}
		changes = append(changes, change)
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Timestamp.After(changes[j].Timestamp) })
	limit := filter.Limit
	if limit <= 0 || limit > s.opts.MaxRecords {
		limit = s.opts.MaxRecords
	}
	if len(changes) > limit {
		changes = changes[:limit]
	}
	return changes, nil
}

func (s *Store) Rollback(id, actor string, force bool) (Change, error) {
	original, err := s.Get(id)
	if err != nil {
		return Change{}, err
	}
	if !original.RollbackSupported {
		return Change{}, ErrRollbackUnsupported
	}
	if !filepath.IsAbs(original.Target) {
		return Change{}, errors.New("recorded target is not absolute")
	}
	lock := s.lockFor(original.Target)
	lock.Lock()
	defer lock.Unlock()
	info, err := os.Lstat(original.Target)
	if err != nil {
		return Change{}, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Change{}, errors.New("rollback target must be a regular non-symlink file")
	}
	canonical, err := filepath.EvalSymlinks(original.Target)
	if err != nil {
		return Change{}, err
	}
	if filepath.Clean(canonical) != filepath.Clean(original.Target) {
		return Change{}, errors.New("rollback target path now traverses a symlink")
	}
	current, err := readBounded(original.Target, s.opts.MaxTargetBytes)
	if err != nil {
		return Change{}, err
	}
	if !force && hash(current) != original.AfterHash {
		return Change{}, ErrConflict
	}
	before, err := os.ReadFile(filepath.Join(s.dir, id, "before"))
	if err != nil {
		return Change{}, err
	}
	if hash(before) != original.BeforeHash {
		return Change{}, errors.New("backup hash does not match metadata")
	}
	change := Change{Timestamp: s.opts.Now().UTC(), Actor: actor, Operation: "change_rollback", Target: original.Target, Description: "Rollback " + id, BeforeHash: hash(current), AfterHash: hash(before), Status: "pending", RollbackSupported: true, RollbackOf: id}
	if err = s.persist(&change, current, before); err != nil {
		return Change{}, err
	}
	if err = atomicReplace(original.Target, before, info.Mode().Perm()); err != nil {
		change.Status = "failed"
		change.Error = err.Error()
		_ = s.updateMetadata(change)
		return Change{}, err
	}
	change.Status = "applied"
	if err = s.updateMetadata(change); err != nil {
		return Change{}, err
	}
	_ = s.Prune()
	return change, nil
}

func (s *Store) lockFor(target string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock := s.targetLocks[target]
	if lock == nil {
		lock = &sync.Mutex{}
		s.targetLocks[target] = lock
	}
	return lock
}

func (s *Store) updateMetadata(change Change) error {
	data, err := json.MarshalIndent(change, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicReplace(filepath.Join(s.dir, change.ID, "metadata.json"), data, 0o600)
}

func (s *Store) Prune() error {
	changes, err := s.List(ListFilter{Limit: s.opts.MaxRecords})
	if err != nil {
		return err
	}
	all, err := s.listAll()
	if err != nil {
		return err
	}
	keepCount := s.opts.MaxRecords
	cutoff := time.Time{}
	if s.opts.RetentionDays > 0 {
		cutoff = s.opts.Now().UTC().Add(-time.Duration(s.opts.RetentionDays) * 24 * time.Hour)
	}
	_ = changes
	for i, change := range all {
		remove := i >= keepCount || (!cutoff.IsZero() && change.Timestamp.Before(cutoff))
		if !remove {
			continue
		}
		if s.opts.OnPrune != nil {
			if err = s.opts.OnPrune(change); err != nil {
				return err
			}
		}
		target := filepath.Join(s.dir, change.ID)
		if !idPattern.MatchString(change.ID) {
			return errors.New("refusing to prune invalid change id")
		}
		if err = os.RemoveAll(target); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) listAll() ([]Change, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := []Change{}
	for _, e := range entries {
		if e.IsDir() && idPattern.MatchString(e.Name()) {
			c, err := s.Get(e.Name())
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	return out, nil
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > max {
		return nil, ErrTooLarge
	}
	return os.ReadFile(path)
}
func writeFileSync(path string, data []byte, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
func atomicReplace(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".remoteops-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(mode); err == nil {
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
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(dir)
}
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
