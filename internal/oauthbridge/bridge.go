// Package oauthbridge adapts the durable local OAuth store to the protocol,
// browser UI, and Agent Smith authentication boundaries.
package oauthbridge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nfraynor/agent-smith/internal/auth"
	"github.com/nfraynor/agent-smith/internal/localoauth"
	"github.com/nfraynor/agent-smith/internal/oauthserver"
	"github.com/nfraynor/agent-smith/internal/oauthui"
	"github.com/nfraynor/agent-smith/internal/permissions"
)

type Bridge struct {
	Store    *localoauth.Store
	Issuer   string
	Resource string
	Now      func() time.Time
	mu       sync.Mutex
	pending  map[string]pendingAuthorization
}

type pendingAuthorization struct {
	Request        oauthserver.AuthorizationRequest
	ExpiresAt      time.Time
	ApprovedUserID string
}

func New(store *localoauth.Store, issuer, resource string) (*Bridge, error) {
	if store == nil || strings.TrimSpace(issuer) == "" || strings.TrimSpace(resource) == "" {
		return nil, errors.New("OAuth store, issuer, and resource are required")
	}
	return &Bridge{Store: store, Issuer: strings.TrimSuffix(issuer, "/"), Resource: resource, Now: time.Now, pending: make(map[string]pendingAuthorization)}, nil
}

func (b *Bridge) RegisterClient(input oauthserver.ClientRegistration) (oauthserver.Client, error) {
	client, err := b.Store.RegisterClient(localoauth.ClientRegistration{Name: input.Name, RedirectURIs: input.RedirectURIs, Source: "dcr"})
	return protocolClient(client), mapStoreError(err)
}

func (b *Bridge) GetClient(id string) (oauthserver.Client, error) {
	client, err := b.Store.GetClient(id)
	return protocolClient(client), mapStoreError(err)
}

func (b *Bridge) CreateAuthorizationCode(input oauthserver.AuthorizationGrant, ttl time.Duration) (string, error) {
	return b.Store.CreateAuthorizationCode(localoauth.AuthorizationGrant{UserID: input.UserID, ClientID: input.ClientID, RedirectURI: input.RedirectURI, Resource: input.Resource, CodeChallenge: input.CodeChallenge, Scopes: input.Scopes}, ttl)
}

func (b *Bridge) ConsumeAuthorizationCode(raw string, input oauthserver.CodeBinding) (oauthserver.AuthorizationGrant, error) {
	grant, err := b.Store.ConsumeAuthorizationCode(raw, localoauth.CodeBinding{ClientID: input.ClientID, RedirectURI: input.RedirectURI, Resource: input.Resource, CodeChallenge: input.CodeChallenge})
	return oauthserver.AuthorizationGrant{UserID: grant.UserID, ClientID: grant.ClientID, RedirectURI: grant.RedirectURI, Resource: grant.Resource, CodeChallenge: grant.CodeChallenge, Scopes: grant.Scopes}, mapStoreError(err)
}

func (b *Bridge) IssueTokenPair(input oauthserver.TokenGrant, accessTTL, refreshTTL time.Duration) (oauthserver.TokenPair, error) {
	pair, err := b.Store.IssueTokenPair(localoauth.TokenGrant{UserID: input.UserID, ClientID: input.ClientID, Resource: input.Resource, Scopes: input.Scopes}, accessTTL, refreshTTL)
	return protocolPair(pair), mapStoreError(err)
}

func (b *Bridge) RotateRefresh(raw string, input oauthserver.RefreshBinding, accessTTL, refreshTTL time.Duration) (oauthserver.TokenPair, error) {
	pair, err := b.Store.RotateRefresh(raw, localoauth.RefreshBinding{ClientID: input.ClientID, Resource: input.Resource}, accessTTL, refreshTTL)
	return protocolPair(pair), mapStoreError(err)
}

func (b *Bridge) RevokeToken(raw, clientID string) error {
	return mapStoreError(b.Store.RevokeToken(raw, clientID))
}

func protocolClient(client localoauth.Client) oauthserver.Client {
	return oauthserver.Client{ID: client.ID, Name: client.Name, RedirectURIs: client.RedirectURIs, CreatedAt: client.CreatedAt, Disabled: client.Disabled}
}

func protocolPair(pair localoauth.TokenPair) oauthserver.TokenPair {
	return oauthserver.TokenPair{AccessToken: pair.AccessToken, RefreshToken: pair.RefreshToken, AccessExpiresAt: pair.AccessExpiresAt, RefreshExpiresAt: pair.RefreshExpiresAt}
}

func mapStoreError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, localoauth.ErrNotFound) {
		return oauthserver.ErrNotFound
	}
	if errors.Is(err, localoauth.ErrBindingMismatch) {
		return oauthserver.ErrBindingMismatch
	}
	if errors.Is(err, localoauth.ErrConsumed) || errors.Is(err, localoauth.ErrExpired) || errors.Is(err, localoauth.ErrRevoked) || errors.Is(err, localoauth.ErrDisabled) {
		return oauthserver.ErrInvalidGrant
	}
	return err
}

// Authorize resumes only server-created opaque transactions and derives identity
// from the host-only browser session cookie.
func (b *Bridge) Authorize(_ context.Context, request *http.Request, input oauthserver.AuthorizationRequest) (oauthserver.AuthorizationDecision, error) {
	transaction := request.URL.Query().Get("_remoteops_transaction")
	cookie, err := request.Cookie(oauthui.SessionCookieName)
	if err == nil {
		_, user, sessionErr := b.Store.GetSession(cookie.Value)
		if sessionErr == nil && user.Enabled && !user.MustChangePassword {
			if transaction != "" {
				b.mu.Lock()
				pending, ok := b.pending[transaction]
				if ok && pending.ApprovedUserID == user.ID {
					delete(b.pending, transaction)
				}
				denied := ok && pending.ApprovedUserID == "denied:"+user.ID
				if denied {
					delete(b.pending, transaction)
				}
				b.mu.Unlock()
				if denied {
					return oauthserver.AuthorizationDecision{}, nil
				}
				if ok && pending.ApprovedUserID == user.ID {
					return oauthserver.AuthorizationDecision{UserID: user.ID}, nil
				}
				if ok {
					return oauthserver.AuthorizationDecision{LoginURL: b.Issuer + "/oauth/consent?transaction=" + url.QueryEscape(transaction)}, nil
				}
			}
			created, createErr := b.createPending(input)
			if createErr != nil {
				return oauthserver.AuthorizationDecision{}, createErr
			}
			return oauthserver.AuthorizationDecision{LoginURL: b.Issuer + "/oauth/consent?transaction=" + url.QueryEscape(created)}, nil
		}
	}
	if transaction != "" {
		b.mu.Lock()
		_, ok := b.pending[transaction]
		b.mu.Unlock()
		if ok {
			return oauthserver.AuthorizationDecision{LoginURL: b.Issuer + "/oauth/login?transaction=" + url.QueryEscape(transaction)}, nil
		}
	}
	token, err := b.createPending(input)
	if err != nil {
		return oauthserver.AuthorizationDecision{}, err
	}
	return oauthserver.AuthorizationDecision{LoginURL: b.Issuer + "/oauth/login?transaction=" + url.QueryEscape(token)}, nil
}

func (b *Bridge) createPending(input oauthserver.AuthorizationRequest) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupLocked()
	if len(b.pending) >= 1024 {
		return "", errors.New("too many pending authorization transactions")
	}
	b.pending[token] = pendingAuthorization{Request: input, ExpiresAt: b.Now().Add(10 * time.Minute)}
	return token, nil
}

// ResumeAuthorization restores a validated authorization request after local login.
// The opaque transaction never contains OAuth parameters or credentials.
func (b *Bridge) ResumeAuthorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/oauth/authorize" {
			token := request.URL.Query().Get("transaction")
			if token != "" {
				b.mu.Lock()
				b.cleanupLocked()
				pending, ok := b.pending[token]
				b.mu.Unlock()
				if !ok {
					http.Error(writer, "Authorization transaction is invalid or expired.", http.StatusBadRequest)
					return
				}
				request = request.Clone(request.Context())
				request.URL = cloneURL(request.URL)
				values := authorizationQuery(pending.Request)
				values.Set("_remoteops_transaction", token)
				request.URL.RawQuery = values.Encode()
			}
		}
		next.ServeHTTP(writer, request)
	})
}

func (b *Bridge) cleanupLocked() {
	now := b.Now()
	for token, transaction := range b.pending {
		if !transaction.ExpiresAt.After(now) {
			delete(b.pending, token)
		}
	}
}

func authorizationQuery(input oauthserver.AuthorizationRequest) url.Values {
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {input.ClientID},
		"redirect_uri":          {input.RedirectURI},
		"resource":              {input.Resource},
		"scope":                 {strings.Join(input.Scopes, " ")},
		"code_challenge":        {input.CodeChallenge},
		"code_challenge_method": {"S256"},
	}
	if input.State != "" {
		values.Set("state", input.State)
	}
	return values
}

func cloneURL(input *url.URL) *url.URL { copy := *input; return &copy }

func randomToken() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// AccessAuthenticator implements Agent Smith's bearer authentication boundary.
type AccessAuthenticator struct{ Bridge *Bridge }

func (a AccessAuthenticator) Authenticate(_ context.Context, credential string) (auth.Identity, error) {
	grant, err := a.Bridge.Store.AuthenticateAccess(credential, a.Bridge.Resource)
	if err != nil {
		return auth.Identity{}, auth.ErrUnauthenticated
	}
	if !slices.Contains(grant.Scopes, "mcp") {
		return auth.Identity{}, auth.ErrUnauthenticated
	}
	return auth.Identity{Actor: grant.User.Email, Role: grant.User.Role}, nil
}

func (b *Bridge) Authenticate(email, password string) (oauthui.User, error) {
	user, err := b.Store.Authenticate(email, password)
	return uiUser(user), uiError(err)
}

func (b *Bridge) VerifyPassword(userID, password string) error {
	return uiError(b.Store.VerifyPassword(userID, password))
}

func (b *Bridge) CreateSession(userID string, ttl time.Duration) (oauthui.SessionCredentials, error) {
	credentials, err := b.Store.CreateSession(userID, ttl)
	return oauthui.SessionCredentials{Token: credentials.Token, CSRFToken: credentials.CSRFToken, ExpiresAt: credentials.Session.ExpiresAt}, uiError(err)
}

func (b *Bridge) GetSession(raw string) (oauthui.Session, oauthui.User, error) {
	session, user, err := b.Store.GetSession(raw)
	return oauthui.Session{ID: session.ID, UserID: session.UserID, ExpiresAt: session.ExpiresAt}, uiUser(user), uiError(err)
}

func (b *Bridge) ValidateCSRF(sessionToken, csrfToken string) error {
	return uiError(b.Store.ValidateCSRF(sessionToken, csrfToken))
}
func (b *Bridge) RevokeSession(raw string) error { return uiError(b.Store.RevokeSession(raw)) }
func (b *Bridge) ChangePassword(userID, current, next string) error {
	return uiError(b.Store.ChangePassword(userID, current, next))
}

func (b *Bridge) ListUsers() ([]oauthui.User, error) {
	users, err := b.Store.ListUsers()
	result := make([]oauthui.User, 0, len(users))
	for _, user := range users {
		result = append(result, uiUser(user))
	}
	return result, uiError(err)
}

func (b *Bridge) CreateUser(input oauthui.CreateUserInput) (oauthui.User, error) {
	user, err := b.Store.CreateUser(input.Email, input.Password, input.Role, input.MustChangePassword)
	return uiUser(user), uiError(err)
}

func (b *Bridge) UpdateUser(input oauthui.UpdateUserInput) error {
	users, err := b.Store.ListUsers()
	if err != nil {
		return uiError(err)
	}
	for _, user := range users {
		if user.ID != input.ID || user.Role != permissions.RoleAdmin || !user.Enabled {
			continue
		}
		if input.Enabled && input.Role == permissions.RoleAdmin {
			break
		}
		remaining := 0
		for _, candidate := range users {
			if candidate.ID != input.ID && candidate.Enabled && candidate.Role == permissions.RoleAdmin {
				remaining++
			}
		}
		if remaining == 0 {
			return errors.New("cannot disable or demote the last enabled administrator")
		}
	}
	role, enabled := input.Role, input.Enabled
	_, err = b.Store.UpdateUser(input.ID, localoauth.UserUpdate{Role: &role, Enabled: &enabled})
	return uiError(err)
}

func (b *Bridge) ResetPassword(userID, password string) error {
	return uiError(b.Store.ResetPassword(userID, password, true))
}
func (b *Bridge) RevokeUserSessions(userID string) error {
	return uiError(b.Store.RevokeUserSessions(userID))
}

func uiUser(user localoauth.User) oauthui.User {
	return oauthui.User{ID: user.ID, Email: user.Email, Role: user.Role, Enabled: user.Enabled, MustChangePassword: user.MustChangePassword}
}

func uiError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, localoauth.ErrInvalidCredentials) {
		return oauthui.ErrInvalidCredentials
	}
	if errors.Is(err, localoauth.ErrNotFound) || errors.Is(err, localoauth.ErrExpired) || errors.Is(err, localoauth.ErrRevoked) || errors.Is(err, localoauth.ErrDisabled) {
		return oauthui.ErrInvalidSession
	}
	return err
}

var _ oauthserver.Store = (*Bridge)(nil)
var _ oauthserver.Authorizer = (*Bridge)(nil)
var _ auth.Authenticator = AccessAuthenticator{}
var _ oauthui.Backend = (*Bridge)(nil)
