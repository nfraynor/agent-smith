// Package locks serializes mutations against the same configured target.
package locks

import (
	"context"
	"errors"
	"sync"
)

var ErrEmptyKey = errors.New("lock key must not be empty")

type Manager struct {
	mu      sync.Mutex
	targets map[string]*entry
}

type entry struct {
	token chan struct{}
	refs  int
}

func New() *Manager { return &Manager{targets: make(map[string]*entry)} }

// Lock waits for exclusive access to key. The returned unlock function is
// idempotent. A canceled waiter cannot strand the target lock.
func (m *Manager) Lock(ctx context.Context, key string) (func(), error) {
	if key == "" {
		return nil, ErrEmptyKey
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.targets == nil {
		m.targets = make(map[string]*entry)
	}
	target := m.targets[key]
	if target == nil {
		target = &entry{token: make(chan struct{}, 1)}
		target.token <- struct{}{}
		m.targets[key] = target
	}
	target.refs++
	m.mu.Unlock()

	select {
	case <-ctx.Done():
		m.releaseReference(key, target)
		return nil, ctx.Err()
	case <-target.token:
		var once sync.Once
		return func() {
			once.Do(func() {
				target.token <- struct{}{}
				m.releaseReference(key, target)
			})
		}, nil
	}
}

func (m *Manager) releaseReference(key string, target *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	target.refs--
	if target.refs == 0 && m.targets[key] == target {
		delete(m.targets, key)
	}
}

func (m *Manager) ActiveTargets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.targets)
}

func FileKey(path string) string                { return "file:" + path }
func ServiceKey(project, service string) string { return "service:" + project + ":" + service }
func ContainerKey(container string) string      { return "container:" + container }
