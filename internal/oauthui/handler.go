// Package oauthui provides the browser-facing login and local account UI for
// RemoteOps' embedded OAuth authorization server.
package oauthui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nfraynor/agent-smith/internal/permissions"
)

const (
	SessionCookieName = "__Host-remoteops_session"
	CSRFCookieName    = "__Host-remoteops_csrf"
	LoginCSRFCookie   = "__Host-remoteops_login_csrf"
)

type styleNonceContextKey struct{}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidSession     = errors.New("invalid session")
)

type User struct {
	ID                 string
	Email              string
	Role               permissions.Role
	Enabled            bool
	MustChangePassword bool
}

type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

type SessionCredentials struct {
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

type CreateUserInput struct {
	Email              string
	Password           string
	Role               permissions.Role
	MustChangePassword bool
}

type UpdateUserInput struct {
	ID      string
	Role    permissions.Role
	Enabled bool
}

// Backend is deliberately narrower than the persistent account store. A small
// adapter at application assembly keeps HTTP concerns out of the store package.
type Backend interface {
	Authenticate(email, password string) (User, error)
	VerifyPassword(userID, password string) error
	CreateSession(userID string, ttl time.Duration) (SessionCredentials, error)
	GetSession(rawToken string) (Session, User, error)
	ValidateCSRF(sessionToken, csrfToken string) error
	RevokeSession(rawToken string) error
	ChangePassword(userID, currentPassword, newPassword string) error
	ListUsers() ([]User, error)
	CreateUser(CreateUserInput) (User, error)
	UpdateUser(UpdateUserInput) error
	ResetPassword(userID, newPassword string) error
	RevokeUserSessions(userID string) error
}

type AuditEvent struct {
	Actor   string
	Action  string
	Target  string
	Success bool
	Reason  string
}

type Options struct {
	PublicOrigin        string
	Backend             Backend
	SessionTTL          time.Duration
	MaxBodyBytes        int64
	PasswordWorkers     int
	Now                 func() time.Time
	Audit               func(AuditEvent)
	LoginAttempts       int
	LoginWindow         time.Duration
	LoginSourceAttempts int
}

type Handler struct {
	origin           string
	backend          Backend
	sessionTTL       time.Duration
	maxBodyBytes     int64
	now              func() time.Time
	audit            func(AuditEvent)
	passwordSlots    chan struct{}
	throttle         *loginThrottle
	mux              *http.ServeMux
	loginTemplate    *template.Template
	passwordTemplate *template.Template
	adminTemplate    *template.Template
}

func New(options Options) (*Handler, error) {
	if options.Backend == nil {
		return nil, errors.New("oauth UI backend is required")
	}
	origin, err := parseOrigin(options.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if options.SessionTTL <= 0 {
		options.SessionTTL = 8 * time.Hour
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = 32 << 10
	}
	if options.PasswordWorkers <= 0 {
		options.PasswordWorkers = 4
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.LoginAttempts <= 0 {
		options.LoginAttempts = 5
	}
	if options.LoginSourceAttempts <= 0 {
		options.LoginSourceAttempts = 20
	}
	if options.LoginWindow <= 0 {
		options.LoginWindow = 5 * time.Minute
	}
	h := &Handler{
		origin: origin, backend: options.Backend, sessionTTL: options.SessionTTL,
		maxBodyBytes: options.MaxBodyBytes, now: options.Now, audit: options.Audit,
		passwordSlots:    make(chan struct{}, options.PasswordWorkers),
		throttle:         newLoginThrottle(options.Now, options.LoginAttempts, options.LoginSourceAttempts, options.LoginWindow),
		loginTemplate:    template.Must(template.New("login").Parse(strings.Replace(enhancedLoginPage, "<link rel='stylesheet' href='/oauth/assets/app.css'>", "<style nonce='{{.StyleNonce}}'>{{.CSS}}</style>", 1))),
		passwordTemplate: template.Must(template.New("password").Parse(strings.Replace(enhancedPasswordPage, "<link rel='stylesheet' href='/oauth/assets/app.css'>", "<style nonce='{{.StyleNonce}}'>{{.CSS}}</style>", 1))),
		adminTemplate: template.Must(template.New("admin").Funcs(template.FuncMap{
			"isViewer":   func(role permissions.Role) bool { return role == permissions.RoleViewer },
			"isOperator": func(role permissions.Role) bool { return role == permissions.RoleOperator },
			"isAdmin":    func(role permissions.Role) bool { return role == permissions.RoleAdmin },
		}).Parse(strings.Replace(enhancedAdminPage, "<link rel='stylesheet' href='/oauth/assets/app.css'>", "<style nonce='{{.StyleNonce}}'>{{.CSS}}</style>", 1))),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/login", h.getLogin)
	mux.HandleFunc("POST /oauth/login", h.postLogin)
	mux.HandleFunc("POST /oauth/logout", h.postLogout)
	mux.HandleFunc("GET /oauth/account/password", h.getPassword)
	mux.HandleFunc("POST /oauth/account/password", h.postPassword)
	mux.HandleFunc("GET /oauth/admin/users", h.getUsers)
	mux.HandleFunc("POST /oauth/admin/users/create", h.postCreateUser)
	mux.HandleFunc("POST /oauth/admin/users/{id}/update", h.postUpdateUser)
	mux.HandleFunc("POST /oauth/admin/users/{id}/reset-password", h.postResetPassword)
	mux.HandleFunc("POST /oauth/admin/users/{id}/revoke-sessions", h.postRevokeSessions)
	h.mux = mux
	return h, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	nonce, err := randomToken()
	if err != nil {
		setSecurityHeaders(writer, "")
		h.serverError(writer)
		return
	}
	setSecurityHeaders(writer, nonce)
	request = request.WithContext(context.WithValue(request.Context(), styleNonceContextKey{}, nonce))
	h.mux.ServeHTTP(writer, request)
}

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	transaction := cleanTransaction(r.URL.Query().Get("transaction"))
	csrf, err := randomToken()
	if err != nil {
		h.serverError(w)
		return
	}
	h.setCookie(w, LoginCSRFCookie, csrf, h.now().Add(10*time.Minute), true)
	h.render(w, r, h.loginTemplate, http.StatusOK, map[string]any{"CSRF": csrf, "Transaction": transaction})
}

func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) {
	if !h.prepareForm(w, r) || !h.validOrigin(r) {
		h.badRequest(w)
		return
	}
	csrfCookie, err := r.Cookie(LoginCSRFCookie)
	if err != nil || !sameToken(csrfCookie.Value, r.PostFormValue("csrf")) {
		h.badRequest(w)
		return
	}
	email := normalizeEmail(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	transaction := cleanTransaction(r.PostFormValue("transaction"))
	if len(email) > 320 || len(password) > 1024 || email == "" || password == "" {
		h.loginFailure(w, r, email, transaction)
		return
	}
	source := remoteHost(r.RemoteAddr)
	if retry, allowed := h.throttle.allow(source, email); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
		h.renderLoginError(w, r, http.StatusTooManyRequests, transaction)
		return
	}
	select {
	case h.passwordSlots <- struct{}{}:
		defer func() { <-h.passwordSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		h.renderLoginError(w, r, http.StatusTooManyRequests, transaction)
		return
	}
	user, err := h.backend.Authenticate(email, password)
	if err != nil || !user.Enabled {
		h.throttle.failure(source, email)
		h.loginFailure(w, r, email, transaction)
		return
	}
	credentials, err := h.backend.CreateSession(user.ID, h.sessionTTL)
	if err != nil {
		h.serverError(w)
		return
	}
	h.throttle.success(source, email)
	h.clearCookie(w, LoginCSRFCookie)
	h.setCookie(w, SessionCookieName, credentials.Token, credentials.ExpiresAt, true)
	h.setCookie(w, CSRFCookieName, credentials.CSRFToken, credentials.ExpiresAt, true)
	h.record(AuditEvent{Actor: user.Email, Action: "login", Success: true})
	if user.MustChangePassword {
		h.redirect(w, r, "/oauth/account/password", transaction)
		return
	}
	h.redirectAfterLogin(w, r, transaction)
}

func (h *Handler) loginFailure(w http.ResponseWriter, r *http.Request, email, transaction string) {
	h.record(AuditEvent{Actor: email, Action: "login", Success: false, Reason: "invalid credentials"})
	h.renderLoginError(w, r, http.StatusUnauthorized, transaction)
}

func (h *Handler) renderLoginError(w http.ResponseWriter, r *http.Request, status int, transaction string) {
	csrf, err := randomToken()
	if err != nil {
		h.serverError(w)
		return
	}
	h.setCookie(w, LoginCSRFCookie, csrf, h.now().Add(10*time.Minute), true)
	h.render(w, r, h.loginTemplate, status, map[string]any{"CSRF": csrf, "Transaction": transaction, "Error": "The email or password was not accepted."})
}

func (h *Handler) getPassword(w http.ResponseWriter, r *http.Request) {
	_, user, token, csrf, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	h.render(w, r, h.passwordTemplate, http.StatusOK, map[string]any{"CSRF": csrf, "Email": user.Email, "Transaction": cleanTransaction(r.URL.Query().Get("transaction"))})
	_ = token
}

func (h *Handler) postPassword(w http.ResponseWriter, r *http.Request) {
	if !h.prepareForm(w, r) || !h.validOrigin(r) {
		h.badRequest(w)
		return
	}
	_, user, token, csrf, ok := h.requireSession(w, r)
	if !ok || !sameToken(csrf, r.PostFormValue("csrf")) || h.backend.ValidateCSRF(token, csrf) != nil {
		if ok {
			h.badRequest(w)
		}
		return
	}
	current, next, confirm := r.PostFormValue("current_password"), r.PostFormValue("new_password"), r.PostFormValue("confirm_password")
	transaction := cleanTransaction(r.PostFormValue("transaction"))
	if next == "" || len(next) > 1024 || next != confirm || h.backend.ChangePassword(user.ID, current, next) != nil {
		h.render(w, r, h.passwordTemplate, http.StatusBadRequest, map[string]any{"CSRF": csrf, "Email": user.Email, "Transaction": transaction, "Error": "The password could not be changed."})
		return
	}
	_ = h.backend.RevokeSession(token)
	credentials, err := h.backend.CreateSession(user.ID, h.sessionTTL)
	if err != nil {
		h.clearAuthCookies(w)
		h.serverError(w)
		return
	}
	h.setCookie(w, SessionCookieName, credentials.Token, credentials.ExpiresAt, true)
	h.setCookie(w, CSRFCookieName, credentials.CSRFToken, credentials.ExpiresAt, true)
	h.record(AuditEvent{Actor: user.Email, Action: "password_change", Target: user.ID, Success: true})
	h.redirectAfterLogin(w, r, transaction)
}

func (h *Handler) postLogout(w http.ResponseWriter, r *http.Request) {
	if !h.prepareForm(w, r) || !h.validOrigin(r) {
		h.badRequest(w)
		return
	}
	_, user, token, csrf, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	if !sameToken(csrf, r.PostFormValue("csrf")) || h.backend.ValidateCSRF(token, csrf) != nil {
		h.badRequest(w)
		return
	}
	_ = h.backend.RevokeSession(token)
	h.clearAuthCookies(w)
	h.record(AuditEvent{Actor: user.Email, Action: "logout", Success: true})
	h.redirect(w, r, "/oauth/login", "")
}

func (h *Handler) getUsers(w http.ResponseWriter, r *http.Request) {
	_, user, _, csrf, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	h.renderAdmin(w, r, http.StatusOK, user, csrf, "", successMessage(r.URL.Query().Get("success")))
}

func (h *Handler) renderAdmin(w http.ResponseWriter, r *http.Request, status int, user User, csrf, message, success string) {
	users, err := h.backend.ListUsers()
	if err != nil {
		h.serverError(w)
		return
	}
	h.render(w, r, h.adminTemplate, status, map[string]any{"CSRF": csrf, "Actor": user, "Users": users, "Error": message, "Success": success})
}

func successMessage(action string) string {
	switch action {
	case "user_create":
		return "User created. You can create another account now."
	case "user_update":
		return "User access updated."
	case "password_reset":
		return "Temporary password set."
	case "sessions_revoke":
		return "Active sessions revoked."
	default:
		return ""
	}
}

func (h *Handler) postCreateUser(w http.ResponseWriter, r *http.Request) {
	h.adminMutation(w, r, "user_create", "new-user", func(_ User) error {
		role, err := permissions.ParseRole(r.PostFormValue("role"))
		if err != nil {
			return err
		}
		_, err = h.backend.CreateUser(CreateUserInput{Email: normalizeEmail(r.PostFormValue("email")), Password: r.PostFormValue("new_password"), Role: role, MustChangePassword: true})
		return err
	})
}

func (h *Handler) postUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := cleanID(r.PathValue("id"))
	h.adminMutation(w, r, "user_update", id, func(_ User) error {
		role, err := permissions.ParseRole(r.PostFormValue("role"))
		if err != nil || id == "" {
			return errors.New("invalid user update")
		}
		return h.backend.UpdateUser(UpdateUserInput{ID: id, Role: role, Enabled: r.PostFormValue("enabled") == "on"})
	})
}

func (h *Handler) postResetPassword(w http.ResponseWriter, r *http.Request) {
	id := cleanID(r.PathValue("id"))
	h.adminMutation(w, r, "password_reset", id, func(_ User) error {
		password := r.PostFormValue("new_password")
		if id == "" || password == "" || len(password) > 1024 {
			return errors.New("invalid password reset")
		}
		return h.backend.ResetPassword(id, password)
	})
}

func (h *Handler) postRevokeSessions(w http.ResponseWriter, r *http.Request) {
	id := cleanID(r.PathValue("id"))
	h.adminMutation(w, r, "sessions_revoke", id, func(_ User) error {
		if id == "" {
			return errors.New("invalid user")
		}
		return h.backend.RevokeUserSessions(id)
	})
}

func (h *Handler) adminMutation(w http.ResponseWriter, r *http.Request, action, target string, mutate func(User) error) {
	if !h.prepareForm(w, r) || !h.validOrigin(r) {
		h.badRequest(w)
		return
	}
	_, actor, token, csrf, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	if !sameToken(csrf, r.PostFormValue("csrf")) || h.backend.ValidateCSRF(token, csrf) != nil {
		h.badRequest(w)
		return
	}
	// Account administration is high impact. Require the administrator's
	// current password on every mutation instead of trusting session age alone.
	if h.backend.VerifyPassword(actor.ID, r.PostFormValue("current_password")) != nil {
		h.record(AuditEvent{Actor: actor.Email, Action: action, Target: target, Success: false, Reason: "recent password confirmation failed"})
		h.renderAdmin(w, r, http.StatusForbidden, actor, csrf, "Your administrator password was not accepted. Enter the password for "+actor.Email+", not the new user's temporary password.", "")
		return
	}
	if err := mutate(actor); err != nil {
		h.record(AuditEvent{Actor: actor.Email, Action: action, Target: target, Success: false, Reason: "operation rejected"})
		h.renderAdmin(w, r, http.StatusBadRequest, actor, csrf, "The account change was not applied. For a new user, use a unique valid email and a temporary password of at least 12 characters.", "")
		return
	}
	h.record(AuditEvent{Actor: actor.Email, Action: action, Target: target, Success: true})
	h.redirect(w, r, "/oauth/admin/users?success="+url.QueryEscape(action), "")
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) (Session, User, string, string, bool) {
	session, user, token, csrf, ok := h.requireSession(w, r)
	if !ok {
		return Session{}, User{}, "", "", false
	}
	if user.Role != permissions.RoleAdmin {
		h.forbidden(w)
		return Session{}, User{}, "", "", false
	}
	return session, user, token, csrf, true
}

func (h *Handler) requireSession(w http.ResponseWriter, r *http.Request) (Session, User, string, string, bool) {
	sessionCookie, err := r.Cookie(SessionCookieName)
	if err != nil || sessionCookie.Value == "" {
		h.redirect(w, r, "/oauth/login", cleanTransaction(r.URL.Query().Get("transaction")))
		return Session{}, User{}, "", "", false
	}
	session, user, err := h.backend.GetSession(sessionCookie.Value)
	if err != nil || !user.Enabled || !session.ExpiresAt.After(h.now()) {
		h.clearAuthCookies(w)
		h.redirect(w, r, "/oauth/login", cleanTransaction(r.URL.Query().Get("transaction")))
		return Session{}, User{}, "", "", false
	}
	csrfCookie, err := r.Cookie(CSRFCookieName)
	if err != nil || csrfCookie.Value == "" || h.backend.ValidateCSRF(sessionCookie.Value, csrfCookie.Value) != nil {
		h.clearAuthCookies(w)
		h.redirect(w, r, "/oauth/login", "")
		return Session{}, User{}, "", "", false
	}
	return session, user, sessionCookie.Value, csrfCookie.Value, true
}

func (h *Handler) prepareForm(w http.ResponseWriter, r *http.Request) bool {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/x-www-form-urlencoded" {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	return r.ParseForm() == nil
}

func (h *Handler) validOrigin(r *http.Request) bool { return r.Header.Get("Origin") == h.origin }

func (h *Handler) redirectAfterLogin(w http.ResponseWriter, r *http.Request, transaction string) {
	if transaction != "" {
		h.redirect(w, r, "/oauth/authorize", transaction)
		return
	}
	h.redirect(w, r, "/oauth/admin/users", "")
}

func (h *Handler) redirect(w http.ResponseWriter, r *http.Request, path, transaction string) {
	if transaction != "" {
		path += "?transaction=" + url.QueryEscape(transaction)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (h *Handler) setCookie(w http.ResponseWriter, name, value string, expires time.Time, httpOnly bool) {
	// The __Host- prefix requires Secure, no Domain, and Path=/; browsers reject
	// prefixed cookies that use a narrower path.
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: httpOnly, SameSite: http.SameSiteLaxMode, Expires: expires, MaxAge: max(1, int(expires.Sub(h.now()).Seconds()))})
}

func (h *Handler) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func (h *Handler) clearAuthCookies(w http.ResponseWriter) {
	h.clearCookie(w, SessionCookieName)
	h.clearCookie(w, CSRFCookieName)
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, page *template.Template, status int, data any) {
	if values, ok := data.(map[string]any); ok {
		// appCSS is a compile-time constant owned by this package, never user input.
		values["CSS"] = template.CSS(appCSS)
		if nonce, ok := r.Context().Value(styleNonceContextKey{}).(string); ok {
			values["StyleNonce"] = nonce
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := page.Execute(w, data); err != nil {
		return
	}
}

func (h *Handler) renderMessage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><title>RemoteOps</title><p>%s</p>", template.HTMLEscapeString(message))
}

func (h *Handler) badRequest(w http.ResponseWriter) {
	h.renderMessage(w, http.StatusBadRequest, "The request could not be accepted.")
}
func (h *Handler) forbidden(w http.ResponseWriter) {
	h.renderMessage(w, http.StatusForbidden, "This account is not permitted to perform that action.")
}
func (h *Handler) serverError(w http.ResponseWriter) {
	h.renderMessage(w, http.StatusInternalServerError, "The request could not be completed.")
}

func (h *Handler) record(event AuditEvent) {
	if h.audit != nil {
		h.audit(event)
	}
}

func setSecurityHeaders(w http.ResponseWriter, styleNonce string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+styleNonce+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func parseOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("oauth UI public origin must be an HTTPS origin")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func sameToken(left, right string) bool {
	if len(left) != len(right) || len(left) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func normalizeEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func cleanTransaction(value string) string {
	if len(value) > 256 {
		return ""
	}
	for _, c := range value {
		if !(c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return ""
		}
	}
	return value
}

func cleanID(value string) string {
	if value == "" || len(value) > 128 {
		return ""
	}
	for _, c := range value {
		if !(c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return ""
		}
	}
	return value
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

type throttleEntry struct {
	windowStart  time.Time
	failures     int
	blockedUntil time.Time
}

type loginThrottle struct {
	mu                    sync.Mutex
	now                   func() time.Time
	accountMax, sourceMax int
	window                time.Duration
	entries               map[string]throttleEntry
}

func newLoginThrottle(now func() time.Time, accountMax, sourceMax int, window time.Duration) *loginThrottle {
	return &loginThrottle{now: now, accountMax: accountMax, sourceMax: sourceMax, window: window, entries: map[string]throttleEntry{}}
}

func (l *loginThrottle) allow(source, email string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, key := range []string{"s:" + source, "a:" + email} {
		entry := l.entries[key]
		if now.Before(entry.blockedUntil) {
			return entry.blockedUntil.Sub(now), false
		}
	}
	return 0, true
}

func (l *loginThrottle) failure(source, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	// Bound memory for deployments exposed through a proxy where source
	// addresses may be numerous or attacker-controlled.
	if len(l.entries) >= 4096 {
		for key, entry := range l.entries {
			if now.Sub(entry.windowStart) >= 2*l.window && !now.Before(entry.blockedUntil) {
				delete(l.entries, key)
			}
		}
	}
	for key, limit := range map[string]int{"s:" + source: l.sourceMax, "a:" + email: l.accountMax} {
		entry := l.entries[key]
		if entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= l.window {
			entry = throttleEntry{windowStart: now}
		}
		entry.failures++
		if entry.failures >= limit {
			over := min(entry.failures-limit, 6)
			entry.blockedUntil = now.Add(time.Second * time.Duration(1<<over))
		}
		l.entries[key] = entry
	}
	if len(l.entries) > 8192 {
		// Account keys retain the useful protection; discard old source keys
		// first to keep the structure bounded under source-address flooding.
		for key := range l.entries {
			if strings.HasPrefix(key, "s:") && key != "s:"+source {
				delete(l.entries, key)
			}
		}
	}
}

func (l *loginThrottle) success(source, email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, "a:"+email)
	// Preserve the source counter so successful requests cannot be used to clear
	// protection for password spraying against other accounts.
}
