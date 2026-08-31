// Package auth authenticates RemoteOps requests and carries identity in context.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

var ErrUnauthenticated = errors.New("unauthenticated")

type Identity struct {
	Actor string           `json:"actor"`
	Role  permissions.Role `json:"role"`
}

type Authenticator interface {
	Authenticate(ctx context.Context, credential string) (Identity, error)
}

type Bearer struct {
	tokenHash [sha256.Size]byte
	identity  Identity
}

func NewBearer(token, actor string, role permissions.Role) (*Bearer, error) {
	if token == "" {
		return nil, errors.New("bearer token must not be empty")
	}
	if strings.TrimSpace(actor) == "" {
		return nil, errors.New("bearer actor must not be empty")
	}
	if _, err := permissions.ParseRole(string(role)); err != nil {
		return nil, err
	}
	return &Bearer{tokenHash: sha256.Sum256([]byte(token)), identity: Identity{Actor: actor, Role: role}}, nil
}

func (b *Bearer) Authenticate(_ context.Context, credential string) (Identity, error) {
	candidate := sha256.Sum256([]byte(credential))
	if subtle.ConstantTimeCompare(candidate[:], b.tokenHash[:]) != 1 {
		return Identity{}, ErrUnauthenticated
	}
	return b.identity, nil
}

type contextKey struct{}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(contextKey{}).(Identity)
	return identity, ok
}

type Attempt struct {
	Actor   string
	Success bool
	Reason  string
}

// Middleware authenticates one RFC 6750-style Authorization header. OnAttempt
// receives metadata only and is never passed the header or credential.
type Middleware struct {
	Authenticator Authenticator
	OnAttempt     func(Attempt)
}

func (m Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if m.Authenticator == nil {
			m.reject(writer, "authentication is not configured")
			return
		}
		headers := request.Header.Values("Authorization")
		if len(headers) != 1 {
			m.reject(writer, "a single bearer authorization header is required")
			return
		}
		credential, ok := parseBearer(headers[0])
		if !ok {
			m.reject(writer, "a valid bearer authorization header is required")
			return
		}
		identity, err := m.Authenticator.Authenticate(request.Context(), credential)
		if err != nil {
			m.reject(writer, "invalid credentials")
			return
		}
		if m.OnAttempt != nil {
			m.OnAttempt(Attempt{Actor: identity.Actor, Success: true})
		}
		next.ServeHTTP(writer, request.WithContext(WithIdentity(request.Context(), identity)))
	})
}

func parseBearer(header string) (string, bool) {
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func (m Middleware) reject(writer http.ResponseWriter, reason string) {
	if m.OnAttempt != nil {
		m.OnAttempt(Attempt{Success: false, Reason: reason})
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("WWW-Authenticate", `Bearer realm="remoteops"`)
	writer.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"code": "UNAUTHENTICATED", "message": "Valid bearer authentication is required.",
	})
}
