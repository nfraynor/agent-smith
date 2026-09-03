package oauthbridge

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/nfraynor/agent-smith/internal/localoauth"
	"github.com/nfraynor/agent-smith/internal/oauthui"
)

func (b *Bridge) ConsentHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		nonce, err := consentNonce()
		if err != nil {
			setConsentHeaders(writer, "", "")
			http.Error(writer, "The request could not be completed.", http.StatusInternalServerError)
			return
		}
		setConsentHeaders(writer, nonce, "")
		switch request.Method {
		case http.MethodGet:
			b.getConsent(writer, request, nonce)
		case http.MethodPost:
			b.postConsent(writer, request, nonce)
		default:
			writer.Header().Set("Allow", "GET, POST")
			http.Error(writer, "Method not allowed.", http.StatusMethodNotAllowed)
		}
	})
}

func (b *Bridge) getConsent(writer http.ResponseWriter, request *http.Request, styleNonce string) {
	transaction := request.URL.Query().Get("transaction")
	pending, ok := b.pendingTransaction(transaction)
	if !ok {
		http.Error(writer, "Authorization transaction is invalid or expired.", http.StatusBadRequest)
		return
	}
	setConsentHeaders(writer, styleNonce, pending.Request.RedirectURI)
	sessionCookie, user, ok := b.consentUser(writer, request, transaction)
	if !ok {
		return
	}
	csrfCookie, err := request.Cookie(oauthui.CSRFCookieName)
	if err != nil || b.Store.ValidateCSRF(sessionCookie, csrfCookie.Value) != nil {
		http.Redirect(writer, request, "/oauth/login?transaction="+url.QueryEscape(transaction), http.StatusSeeOther)
		return
	}
	client, err := b.Store.GetClient(pending.Request.ClientID)
	if err != nil {
		http.Error(writer, "Authorization client is unavailable.", http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.Execute(writer, map[string]any{
		"CSS": template.CSS(oauthui.FoundationCSS + consentCSS), "StyleNonce": styleNonce,
		"Client": client.Name, "ClientInitial": clientInitial(client.Name), "Email": user.Email, "Role": user.Role,
		"Permissions": consentPermissions(pending.Request.Scopes), "Transaction": transaction, "CSRF": csrfCookie.Value,
	})
}

func (b *Bridge) postConsent(writer http.ResponseWriter, request *http.Request, styleNonce string) {
	if request.Header.Get("Origin") != b.Issuer || !strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		http.Error(writer, "The request could not be accepted.", http.StatusBadRequest)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 32<<10)
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "The request could not be accepted.", http.StatusBadRequest)
		return
	}
	transaction := request.PostForm.Get("transaction")
	pending, ok := b.pendingTransaction(transaction)
	if !ok {
		http.Error(writer, "Authorization transaction is invalid or expired.", http.StatusBadRequest)
		return
	}
	setConsentHeaders(writer, styleNonce, pending.Request.RedirectURI)
	sessionCookie, user, ok := b.consentUser(writer, request, transaction)
	if !ok {
		return
	}
	csrfCookie, err := request.Cookie(oauthui.CSRFCookieName)
	if err != nil || !sameConsentToken(csrfCookie.Value, request.PostForm.Get("csrf")) || b.Store.ValidateCSRF(sessionCookie, csrfCookie.Value) != nil {
		http.Error(writer, "The request could not be accepted.", http.StatusBadRequest)
		return
	}
	decision := request.PostForm.Get("decision")
	b.mu.Lock()
	pending, exists := b.pending[transaction]
	if exists {
		if decision == "approve" {
			pending.ApprovedUserID = user.ID
		} else {
			pending.ApprovedUserID = "denied:" + user.ID
		}
		b.pending[transaction] = pending
	}
	b.mu.Unlock()
	if !exists {
		http.Error(writer, "Authorization transaction is invalid or expired.", http.StatusBadRequest)
		return
	}
	http.Redirect(writer, request, "/oauth/authorize?transaction="+url.QueryEscape(transaction), http.StatusSeeOther)
}

func (b *Bridge) consentUser(writer http.ResponseWriter, request *http.Request, transaction string) (string, localoauth.User, bool) {
	cookie, err := request.Cookie(oauthui.SessionCookieName)
	if err != nil {
		http.Redirect(writer, request, "/oauth/login?transaction="+url.QueryEscape(transaction), http.StatusSeeOther)
		return "", localoauth.User{}, false
	}
	_, user, err := b.Store.GetSession(cookie.Value)
	if err != nil || !user.Enabled || user.MustChangePassword {
		http.Redirect(writer, request, "/oauth/login?transaction="+url.QueryEscape(transaction), http.StatusSeeOther)
		return "", localoauth.User{}, false
	}
	return cookie.Value, user, true
}

func (b *Bridge) pendingTransaction(token string) (pendingAuthorization, bool) {
	if token == "" {
		return pendingAuthorization{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupLocked()
	pending, ok := b.pending[token]
	return pending, ok
}

func setConsentHeaders(writer http.ResponseWriter, styleNonce, redirectURI string) {
	formAction := "'self'"
	if source := consentFormActionSource(redirectURI); source != "" {
		formAction += " " + source
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+styleNonce+"'; form-action "+formAction+"; base-uri 'none'; frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
}

func consentFormActionSource(redirectURI string) string {
	callback, err := url.Parse(redirectURI)
	if err != nil || callback.Scheme != "https" || callback.Host == "" || callback.User != nil {
		return ""
	}
	return callback.Scheme + "://" + callback.Host
}

type consentPermission struct {
	Title       string
	Description string
}

func consentPermissions(scopes []string) []consentPermission {
	permissions := make([]consentPermission, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case "mcp":
			permissions = append(permissions, consentPermission{Title: "Use Agent Smith tools", Description: "Perform only the operations allowed by your Agent Smith role."})
		case "offline_access":
			permissions = append(permissions, consentPermission{Title: "Stay connected", Description: "Refresh access securely without asking you to sign in every time."})
		}
	}
	return permissions
}

func clientInitial(name string) string {
	runes := []rune(strings.TrimSpace(name))
	if len(runes) == 0 {
		return "?"
	}
	return strings.ToUpper(string(runes[0]))
}

func consentNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func sameConsentToken(left, right string) bool {
	return left != "" && len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
