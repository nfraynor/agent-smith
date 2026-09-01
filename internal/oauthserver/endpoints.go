package oauthserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.allowRegistration() {
		w.Header().Set("Retry-After", "60")
		s.oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "client registration rate limit exceeded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request registrationRequest
	if err := decoder.Decode(&request); err != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid registration document")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "registration document must contain one JSON object")
		return
	}
	if request.TokenEndpointAuthMethod == "" {
		request.TokenEndpointAuthMethod = "none"
	}
	if request.TokenEndpointAuthMethod != "none" || len(request.RedirectURIs) == 0 || len(request.RedirectURIs) > 8 || strings.TrimSpace(request.ClientName) == "" || len(request.ClientName) > 128 {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only bounded named public clients are supported")
		return
	}
	if len(request.GrantTypes) > 0 && !sameSet(request.GrantTypes, []string{"authorization_code", "refresh_token"}) && !sameSet(request.GrantTypes, []string{"authorization_code"}) {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant types")
		return
	}
	if len(request.ResponseTypes) > 0 && !sameSet(request.ResponseTypes, []string{"code"}) {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response types")
		return
	}
	redirects := make([]string, 0, len(request.RedirectURIs))
	seen := map[string]bool{}
	for _, redirect := range request.RedirectURIs {
		if validateRedirectURI(redirect) != nil || !slices.Contains(s.config.AllowedRedirectURIs, redirect) || seen[redirect] {
			s.oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URI is not allowed")
			return
		}
		seen[redirect] = true
		redirects = append(redirects, redirect)
	}
	client, err := s.store.RegisterClient(ClientRegistration{Name: request.ClientName, RedirectURIs: redirects})
	if err != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "client registration failed")
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": client.ID, "client_id_issued_at": unixTime(client.CreatedAt), "redirect_uris": client.RedirectURIs,
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "client_name": client.Name,
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "resource", "scope", "state"} {
		if len(query[key]) > 1 || (key == "state" && len(query.Get(key)) > 512) {
			s.oauthError(w, http.StatusBadRequest, "invalid_request", "duplicate or oversized authorization parameter")
			return
		}
	}
	clientID, redirectURI := query.Get("client_id"), query.Get("redirect_uri")
	client, err := s.store.GetClient(clientID)
	if err != nil || client.Disabled || !slices.Contains(client.RedirectURIs, redirectURI) {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "invalid client or redirect URI")
		return
	}
	fail := func(code, description string) {
		redirectAuthorizationError(w, r, redirectURI, query.Get("state"), s.config.Issuer, code, description)
	}
	if query.Get("response_type") != "code" {
		fail("unsupported_response_type", "response_type must be code")
		return
	}
	if query.Get("code_challenge_method") != "S256" || !validChallenge(query.Get("code_challenge")) {
		fail("invalid_request", "PKCE S256 is required")
		return
	}
	if query.Get("resource") != s.config.Resource {
		fail("invalid_target", "resource is not this MCP server")
		return
	}
	scopes, ok := parseScopes(query.Get("scope"))
	if !ok {
		fail("invalid_scope", "scope must include mcp")
		return
	}
	request := AuthorizationRequest{ClientID: clientID, RedirectURI: redirectURI, Resource: query.Get("resource"), State: query.Get("state"), CodeChallenge: query.Get("code_challenge"), Scopes: scopes}
	decision, err := s.authorizer.Authorize(r.Context(), r, request)
	if err != nil {
		fail("server_error", "authorization could not be completed")
		return
	}
	if decision.LoginURL != "" {
		login, parseErr := url.Parse(decision.LoginURL)
		issuer, _ := url.Parse(s.config.Issuer)
		if parseErr != nil || !login.IsAbs() || login.Host != issuer.Host || login.Scheme != issuer.Scheme {
			s.oauthError(w, http.StatusInternalServerError, "server_error", "invalid local login continuation")
			return
		}
		http.Redirect(w, r, decision.LoginURL, http.StatusFound)
		return
	}
	if strings.TrimSpace(decision.UserID) == "" {
		fail("access_denied", "the resource owner denied the request")
		return
	}
	code, err := s.store.CreateAuthorizationCode(AuthorizationGrant{UserID: decision.UserID, ClientID: clientID, RedirectURI: redirectURI, Resource: s.config.Resource, CodeChallenge: request.CodeChallenge, Scopes: scopes}, s.config.AuthorizationCodeTTL)
	if err != nil {
		fail("server_error", "authorization could not be completed")
		return
	}
	location, _ := url.Parse(redirectURI)
	values := location.Query()
	values.Set("code", code)
	if request.State != "" {
		values.Set("state", request.State)
	}
	values.Set("iss", s.config.Issuer)
	location.RawQuery = values.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "public clients must not authenticate")
		return
	}
	if err := parseForm(w, r); err != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if duplicateFormValues(r.PostForm) {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "duplicate form parameter")
		return
	}
	clientID := r.PostForm.Get("client_id")
	client, err := s.store.GetClient(clientID)
	if err != nil || client.Disabled {
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown public client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, client)
	case "refresh_token":
		s.refresh(w, r, client)
	default:
		s.oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type is not supported")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, client Client) {
	challenge, ok := pkceChallenge(r.PostForm.Get("code_verifier"))
	if !ok || r.PostForm.Get("redirect_uri") == "" || r.PostForm.Get("resource") != s.config.Resource {
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	grant, err := s.store.ConsumeAuthorizationCode(r.PostForm.Get("code"), CodeBinding{ClientID: client.ID, RedirectURI: r.PostForm.Get("redirect_uri"), Resource: s.config.Resource, CodeChallenge: challenge})
	if err != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid")
		return
	}
	refreshTTL := s.config.RefreshTokenTTL
	if !slices.Contains(grant.Scopes, "offline_access") {
		refreshTTL = 0
	}
	pair, err := s.store.IssueTokenPair(TokenGrant{UserID: grant.UserID, ClientID: grant.ClientID, Resource: grant.Resource, Scopes: grant.Scopes}, s.config.AccessTokenTTL, refreshTTL)
	if err != nil {
		s.oauthError(w, http.StatusInternalServerError, "server_error", "token could not be issued")
		return
	}
	s.writeTokenPair(w, pair, grant.Scopes)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, client Client) {
	if r.PostForm.Get("scope") != "" {
		s.oauthError(w, http.StatusBadRequest, "invalid_scope", "refresh cannot change the original scopes")
		return
	}
	if r.PostForm.Get("resource") != s.config.Resource {
		s.oauthError(w, http.StatusBadRequest, "invalid_target", "resource is not this MCP server")
		return
	}
	pair, err := s.store.RotateRefresh(r.PostForm.Get("refresh_token"), RefreshBinding{ClientID: client.ID, Resource: s.config.Resource}, s.config.AccessTokenTTL, s.config.RefreshTokenTTL)
	if err != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
		return
	}
	s.writeTokenPair(w, pair, nil)
}

func (s *Server) writeTokenPair(w http.ResponseWriter, pair TokenPair, scopes []string) {
	response := map[string]any{"access_token": pair.AccessToken, "token_type": "Bearer", "expires_in": expiresIn(s.config.Now(), pair.AccessExpiresAt)}
	if pair.RefreshToken != "" {
		response["refresh_token"] = pair.RefreshToken
	}
	if len(scopes) > 0 {
		response["scope"] = joinScopes(scopes)
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "public clients must not authenticate")
		return
	}
	if err := parseForm(w, r); err != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if duplicateFormValues(r.PostForm) {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "duplicate form parameter")
		return
	}
	client, err := s.store.GetClient(r.PostForm.Get("client_id"))
	if err != nil || client.Disabled {
		s.oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown public client")
		return
	}
	if token := r.PostForm.Get("token"); token != "" {
		_ = s.store.RevokeToken(token, client.ID)
	}
	w.WriteHeader(http.StatusOK)
}

func redirectAuthorizationError(w http.ResponseWriter, r *http.Request, redirectURI, state, issuer, code, description string) {
	location, _ := url.Parse(redirectURI)
	query := location.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	query.Set("iss", issuer)
	location.RawQuery = query.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func sameSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]struct{}, len(left))
	for _, value := range left {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		if !slices.Contains(right, value) {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validChallenge(challenge string) bool {
	if len(challenge) != 43 {
		return false
	}
	for _, c := range challenge {
		if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func duplicateFormValues(values url.Values) bool {
	for _, entries := range values {
		if len(entries) > 1 {
			return true
		}
	}
	return false
}

func (s *Server) allowRegistration() bool {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	now := s.config.Now()
	if s.registerAt.IsZero() || now.Sub(s.registerAt) >= time.Minute || now.Before(s.registerAt) {
		s.registerAt = now
		s.registerN = 0
	}
	if s.registerN >= 30 {
		return false
	}
	s.registerN++
	return true
}
