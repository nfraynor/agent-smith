package oauthui

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

type fakeSession struct {
	session Session
	user    User
	csrf    string
}

type fakeBackend struct {
	mu              sync.Mutex
	users           []User
	sessions        map[string]fakeSession
	password        string
	authCalls       int
	updated         *UpdateUserInput
	revoked         string
	passwordChanged bool
}

func newFakeBackend(role permissions.Role) *fakeBackend {
	return &fakeBackend{
		users:    []User{{ID: "user-1", Email: "admin@example.com", Role: role, Enabled: true}},
		sessions: map[string]fakeSession{}, password: "correct horse battery staple",
	}
}

func (f *fakeBackend) Authenticate(email, password string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authCalls++
	if email != f.users[0].Email || password != f.password {
		return User{}, ErrInvalidCredentials
	}
	return f.users[0], nil
}

func (f *fakeBackend) VerifyPassword(userID, password string) error {
	if userID != f.users[0].ID || password != f.password {
		return ErrInvalidCredentials
	}
	return nil
}

func (f *fakeBackend) CreateSession(userID string, ttl time.Duration) (SessionCredentials, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	token := "session-" + string(rune('a'+len(f.sessions)))
	csrf := "csrf-" + token
	expires := time.Now().Add(ttl)
	f.sessions[token] = fakeSession{session: Session{ID: token, UserID: userID, ExpiresAt: expires}, user: f.users[0], csrf: csrf}
	return SessionCredentials{Token: token, CSRFToken: csrf, ExpiresAt: expires}, nil
}

func (f *fakeBackend) GetSession(raw string) (Session, User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.sessions[raw]
	if !ok {
		return Session{}, User{}, ErrInvalidSession
	}
	return value.session, value.user, nil
}

func (f *fakeBackend) ValidateCSRF(token, csrf string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.sessions[token]
	if !ok || value.csrf != csrf {
		return errors.New("invalid CSRF")
	}
	return nil
}

func (f *fakeBackend) RevokeSession(raw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, raw)
	f.revoked = raw
	return nil
}

func (f *fakeBackend) ChangePassword(userID, current, next string) error {
	if userID != f.users[0].ID || current != f.password || len(next) < 12 {
		return ErrInvalidCredentials
	}
	f.password = next
	f.passwordChanged = true
	return nil
}

func (f *fakeBackend) ListUsers() ([]User, error) { return append([]User(nil), f.users...), nil }

func (f *fakeBackend) CreateUser(input CreateUserInput) (User, error) {
	user := User{ID: "created", Email: input.Email, Role: input.Role, Enabled: true, MustChangePassword: input.MustChangePassword}
	f.users = append(f.users, user)
	return user, nil
}

func (f *fakeBackend) UpdateUser(input UpdateUserInput) error { f.updated = &input; return nil }
func (f *fakeBackend) ResetPassword(string, string) error     { return nil }
func (f *fakeBackend) RevokeUserSessions(id string) error     { f.revoked = id; return nil }

func newHandler(t *testing.T, backend *fakeBackend, mutate func(*Options)) *Handler {
	t.Helper()
	options := Options{PublicOrigin: "https://this.dev.privacyperfect.com", Backend: backend}
	if mutate != nil {
		mutate(&options)
	}
	handler, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestLoginPageSetsDefensiveHeadersAndHostCookie(t *testing.T) {
	handler := newHandler(t, newFakeBackend(permissions.RoleAdmin), nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://remote.test/login?transaction=abc_123", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	for name, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"} {
		if got := recorder.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("missing restrictive CSP")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != LoginCSRFCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" {
		t.Fatalf("unexpected login CSRF cookie: %#v", cookies)
	}
	if !strings.Contains(recorder.Body.String(), `value="abc_123"`) {
		t.Error("transaction handle was not preserved")
	}
}

func TestLoginRejectsCrossOriginBeforePasswordVerification(t *testing.T) {
	backend := newFakeBackend(permissions.RoleAdmin)
	handler := newHandler(t, backend, nil)
	recorder := httptest.NewRecorder()
	request := formRequest(http.MethodPost, "/login", url.Values{"csrf": {"token"}, "email": {"admin@example.com"}, "password": {backend.password}}, "https://evil.example")
	request.AddCookie(&http.Cookie{Name: LoginCSRFCookie, Value: "token"})
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || backend.authCalls != 0 {
		t.Fatalf("status=%d authCalls=%d", recorder.Code, backend.authCalls)
	}
}

func TestSuccessfulLoginRotatesSessionAndUsesInternalContinuation(t *testing.T) {
	backend := newFakeBackend(permissions.RoleAdmin)
	handler := newHandler(t, backend, nil)
	recorder := httptest.NewRecorder()
	request := formRequest(http.MethodPost, "/login", url.Values{"csrf": {"token"}, "email": {"ADMIN@EXAMPLE.COM"}, "password": {backend.password}, "transaction": {"tx-123"}}, "https://this.dev.privacyperfect.com")
	request.AddCookie(&http.Cookie{Name: LoginCSRFCookie, Value: "token"})
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "attacker-fixed"})
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/oauth/authorize?transaction=tx-123" {
		t.Fatalf("status=%d location=%q body=%s", recorder.Code, recorder.Header().Get("Location"), recorder.Body.String())
	}
	cookies := recorder.Result().Cookies()
	var session, csrf *http.Cookie
	for _, cookie := range cookies {
		switch cookie.Name {
		case SessionCookieName:
			session = cookie
		case CSRFCookieName:
			csrf = cookie
		}
	}
	if session == nil || csrf == nil || session.Value == "attacker-fixed" || !session.HttpOnly || !csrf.HttpOnly || !session.Secure || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected auth cookies: %#v", cookies)
	}
}

func TestLoginDoesNotAcceptRedirectAsTransaction(t *testing.T) {
	backend := newFakeBackend(permissions.RoleAdmin)
	handler := newHandler(t, backend, nil)
	recorder := httptest.NewRecorder()
	request := formRequest(http.MethodPost, "/login", url.Values{"csrf": {"token"}, "email": {backend.users[0].Email}, "password": {backend.password}, "transaction": {"https://evil.example/steal"}}, "https://this.dev.privacyperfect.com")
	request.AddCookie(&http.Cookie{Name: LoginCSRFCookie, Value: "token"})
	handler.ServeHTTP(recorder, request)
	if recorder.Header().Get("Location") != "/admin/users" {
		t.Fatalf("unsafe redirect location %q", recorder.Header().Get("Location"))
	}
}

func TestPasswordChangeRequiresStoredCSRFAndRotatesSession(t *testing.T) {
	backend := newFakeBackend(permissions.RoleAdmin)
	credentials, _ := backend.CreateSession("user-1", time.Hour)
	handler := newHandler(t, backend, nil)

	bad := httptest.NewRecorder()
	badRequest := authenticatedForm("/account/password", credentials, url.Values{"csrf": {"wrong"}, "current_password": {backend.password}, "new_password": {"new correct horse battery"}, "confirm_password": {"new correct horse battery"}})
	handler.ServeHTTP(bad, badRequest)
	if bad.Code != http.StatusBadRequest || backend.passwordChanged {
		t.Fatalf("bad CSRF status=%d changed=%v", bad.Code, backend.passwordChanged)
	}

	good := httptest.NewRecorder()
	goodRequest := authenticatedForm("/account/password", credentials, url.Values{"csrf": {credentials.CSRFToken}, "current_password": {backend.password}, "new_password": {"new correct horse battery"}, "confirm_password": {"new correct horse battery"}})
	handler.ServeHTTP(good, goodRequest)
	if good.Code != http.StatusSeeOther || !backend.passwordChanged || backend.revoked != credentials.Token {
		t.Fatalf("status=%d changed=%v revoked=%q", good.Code, backend.passwordChanged, backend.revoked)
	}
}

func TestAdminMutationRequiresAdminAndPasswordConfirmation(t *testing.T) {
	backend := newFakeBackend(permissions.RoleAdmin)
	credentials, _ := backend.CreateSession("user-1", time.Hour)
	handler := newHandler(t, backend, nil)

	denied := httptest.NewRecorder()
	deniedRequest := authenticatedForm("/admin/users/user-2/update", credentials, url.Values{"csrf": {credentials.CSRFToken}, "current_password": {"wrong"}, "role": {"operator"}, "enabled": {"on"}})
	handler.ServeHTTP(denied, deniedRequest)
	if denied.Code != http.StatusForbidden || backend.updated != nil {
		t.Fatalf("status=%d update=%#v", denied.Code, backend.updated)
	}

	allowed := httptest.NewRecorder()
	allowedRequest := authenticatedForm("/admin/users/user-2/update", credentials, url.Values{"csrf": {credentials.CSRFToken}, "current_password": {backend.password}, "role": {"operator"}, "enabled": {"on"}})
	handler.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusSeeOther || backend.updated == nil || backend.updated.ID != "user-2" || backend.updated.Role != permissions.RoleOperator {
		t.Fatalf("status=%d update=%#v", allowed.Code, backend.updated)
	}
}

func TestViewerCannotReadAdminPage(t *testing.T) {
	backend := newFakeBackend(permissions.RoleViewer)
	credentials, _ := backend.CreateSession("user-1", time.Hour)
	handler := newHandler(t, backend, nil)
	request := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credentials.Token})
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: credentials.CSRFToken})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestAdminPageEscapesAccountData(t *testing.T) {
	backend := newFakeBackend(permissions.RoleAdmin)
	backend.users = append(backend.users, User{ID: "user-2", Email: `<script>alert(1)</script>@example.com`, Role: permissions.RoleViewer, Enabled: true})
	credentials, _ := backend.CreateSession("user-1", time.Hour)
	handler := newHandler(t, backend, nil)
	request := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credentials.Token})
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: credentials.CSRFToken})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "<script>") || !strings.Contains(recorder.Body.String(), "&lt;script&gt;") {
		t.Fatalf("unsafe output: %s", recorder.Body.String())
	}
}

func TestFormBodyIsBounded(t *testing.T) {
	backend := newFakeBackend(permissions.RoleAdmin)
	handler := newHandler(t, backend, func(options *Options) { options.MaxBodyBytes = 64 })
	recorder := httptest.NewRecorder()
	request := formRequest(http.MethodPost, "/login", url.Values{"csrf": {"token"}, "email": {strings.Repeat("a", 100)}, "password": {backend.password}}, "https://this.dev.privacyperfect.com")
	request.AddCookie(&http.Cookie{Name: LoginCSRFCookie, Value: "token"})
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || backend.authCalls != 0 {
		t.Fatalf("status=%d authCalls=%d", recorder.Code, backend.authCalls)
	}
}

func TestInvalidPublicOriginFailsClosed(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://example.com/path", "https://user@example.com", "https://example.com?x=1"} {
		if _, err := New(Options{PublicOrigin: origin, Backend: newFakeBackend(permissions.RoleAdmin)}); err == nil {
			t.Errorf("origin %q was accepted", origin)
		}
	}
}

func formRequest(method, target string, values url.Values, origin string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	request.RemoteAddr = "192.0.2.10:1234"
	return request
}

func authenticatedForm(target string, credentials SessionCredentials, values url.Values) *http.Request {
	request := formRequest(http.MethodPost, target, values, "https://this.dev.privacyperfect.com")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credentials.Token})
	request.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: credentials.CSRFToken})
	return request
}

func readAll(t *testing.T, reader io.Reader) string {
	t.Helper()
	value, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}
