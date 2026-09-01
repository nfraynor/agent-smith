// Package localoauth provides durable local accounts and OAuth credential state.
// It intentionally contains no HTTP or protocol presentation logic.
package localoauth

import (
	"errors"
	"time"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrDisabled           = errors.New("account or client is disabled")
	ErrExpired            = errors.New("credential expired")
	ErrConsumed           = errors.New("credential already consumed")
	ErrRevoked            = errors.New("credential revoked")
	ErrBindingMismatch    = errors.New("credential binding mismatch")
	ErrAlreadyExists      = errors.New("record already exists")
)

type Argon2Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   uint32
	KeyBytes    uint32
}

func DefaultArgon2Params() Argon2Params {
	return Argon2Params{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2, SaltBytes: 16, KeyBytes: 32}
}

type Options struct {
	Path                string
	Now                 func() time.Time
	Argon2              Argon2Params
	PasswordConcurrency int
}

type User struct {
	ID                 string           `json:"id"`
	Email              string           `json:"email"`
	Role               permissions.Role `json:"role"`
	Enabled            bool             `json:"enabled"`
	MustChangePassword bool             `json:"must_change_password"`
	SecurityVersion    uint64           `json:"security_version"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
}

type UserUpdate struct {
	Role               *permissions.Role
	Enabled            *bool
	MustChangePassword *bool
}

type Session struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	ExpiresAt       time.Time `json:"expires_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	SecurityVersion uint64    `json:"security_version"`
}

type SessionCredentials struct {
	Token     string
	CSRFToken string
	Session   Session
}

type ClientRegistration struct {
	Name         string
	RedirectURIs []string
	Source       string
}

type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	Source       string    `json:"source"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AuthorizationGrant struct {
	UserID        string   `json:"user_id"`
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Resource      string   `json:"resource"`
	CodeChallenge string   `json:"code_challenge"`
	Scopes        []string `json:"scopes"`
}

type CodeBinding struct {
	ClientID      string
	RedirectURI   string
	Resource      string
	CodeChallenge string
}

type TokenGrant struct {
	UserID   string
	ClientID string
	Resource string
	Scopes   []string
}

type RefreshBinding struct {
	ClientID string
	Resource string
}

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

type AccessGrant struct {
	User      User
	ClientID  string
	Resource  string
	Scopes    []string
	ExpiresAt time.Time
}
