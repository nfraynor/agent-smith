package oauthbridge

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/nfraynor/agent-smith/internal/localoauth"
	"github.com/nfraynor/agent-smith/internal/oauthui"
)

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize RemoteOps</title></head>
<body><main><h1>Authorize RemoteOps access</h1><p><strong>{{.Client}}</strong> is requesting access to the RemoteOps MCP server as <strong>{{.Email}}</strong>.</p>
<p>Your RemoteOps role remains {{.Role}}. OAuth cannot increase it or enable God Mode.</p>
<form method="post" action="/oauth/consent"><input type="hidden" name="transaction" value="{{.Transaction}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><button name="decision" value="approve">Authorize</button><button name="decision" value="deny">Deny</button></form>
</main></body></html>`))

func (b *Bridge) ConsentHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setConsentHeaders(writer)
		switch request.Method {
		case http.MethodGet:
			b.getConsent(writer, request)
		case http.MethodPost:
			b.postConsent(writer, request)
		default:
			writer.Header().Set("Allow", "GET, POST")
			http.Error(writer, "Method not allowed.", http.StatusMethodNotAllowed)
		}
	})
}

func (b *Bridge) getConsent(writer http.ResponseWriter, request *http.Request) {
	transaction := request.URL.Query().Get("transaction")
	pending, ok := b.pendingTransaction(transaction)
	if !ok {
		http.Error(writer, "Authorization transaction is invalid or expired.", http.StatusBadRequest)
		return
	}
	sessionCookie, user, ok := b.consentUser(writer, request, transaction)
	if !ok {
		return
	}
	csrfCookie, err := request.Cookie(oauthui.CSRFCookieName)
	if err != nil || b.Store.ValidateCSRF(sessionCookie, csrfCookie.Value) != nil {
		http.Redirect(writer, request, "/login?transaction="+url.QueryEscape(transaction), http.StatusSeeOther)
		return
	}
	client, err := b.Store.GetClient(pending.Request.ClientID)
	if err != nil {
		http.Error(writer, "Authorization client is unavailable.", http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTemplate.Execute(writer, map[string]any{"Client": client.Name, "Email": user.Email, "Role": user.Role, "Transaction": transaction, "CSRF": csrfCookie.Value})
}

func (b *Bridge) postConsent(writer http.ResponseWriter, request *http.Request) {
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
	if _, ok := b.pendingTransaction(transaction); !ok {
		http.Error(writer, "Authorization transaction is invalid or expired.", http.StatusBadRequest)
		return
	}
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
		http.Redirect(writer, request, "/login?transaction="+url.QueryEscape(transaction), http.StatusSeeOther)
		return "", localoauth.User{}, false
	}
	_, user, err := b.Store.GetSession(cookie.Value)
	if err != nil || !user.Enabled || user.MustChangePassword {
		http.Redirect(writer, request, "/login?transaction="+url.QueryEscape(transaction), http.StatusSeeOther)
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

func setConsentHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
}

func sameConsentToken(left, right string) bool {
	return left != "" && len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
