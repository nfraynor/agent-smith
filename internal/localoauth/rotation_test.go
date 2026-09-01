package localoauth

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestConcurrentRefreshAllowsOneRotationAndRevokesWinnerOnReplay(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	client, err := store.RegisterClient(ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	binding := RefreshBinding{ClientID: client.ID, Resource: "https://server.example/mcp"}
	first, err := store.IssueTokenPair(TokenGrant{UserID: user.ID, ClientID: client.ID, Resource: binding.Resource, Scopes: []string{"mcp"}}, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		pair TokenPair
		err  error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for range 2 {
		go func() {
			start.Wait()
			pair, rotateErr := store.RotateRefresh(first.RefreshToken, binding, time.Minute, time.Hour)
			results <- result{pair: pair, err: rotateErr}
		}()
	}
	start.Done()
	one, two := <-results, <-results
	var winner TokenPair
	if one.err == nil && errors.Is(two.err, ErrConsumed) {
		winner = one.pair
	} else if two.err == nil && errors.Is(one.err, ErrConsumed) {
		winner = two.pair
	} else {
		t.Fatalf("rotation results = %v, %v", one.err, two.err)
	}
	if _, err = store.RotateRefresh(winner.RefreshToken, binding, time.Minute, time.Hour); !errors.Is(err, ErrRevoked) {
		t.Fatalf("winner's family survived detected replay: %v", err)
	}
}

func TestAuthorizationCodeExpiryAndResourceBinding(t *testing.T) {
	now := time.Now().UTC()
	store := openTestStore(t, &now)
	user := bootstrapTestUser(t, store)
	client, _ := store.RegisterClient(ClientRegistration{Name: "test", RedirectURIs: []string{"https://client.example/callback"}})
	grant := AuthorizationGrant{UserID: user.ID, ClientID: client.ID, RedirectURI: client.RedirectURIs[0], Resource: "https://server.example/mcp", CodeChallenge: "challenge", Scopes: []string{"mcp"}}
	code, err := store.CreateAuthorizationCode(grant, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	binding := CodeBinding{ClientID: client.ID, RedirectURI: grant.RedirectURI, Resource: "https://other.example/mcp", CodeChallenge: grant.CodeChallenge}
	if _, err = store.ConsumeAuthorizationCode(code, binding); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("resource binding error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	binding.Resource = grant.Resource
	if _, err = store.ConsumeAuthorizationCode(code, binding); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry error = %v", err)
	}
}
