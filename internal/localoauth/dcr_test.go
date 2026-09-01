package localoauth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestClientRegistrationDeduplicatesRedirectSet(t *testing.T) {
	now := time.Now()
	store := openTestStore(t, &now)
	first, err := store.RegisterClient(ClientRegistration{Name: "ChatGPT", RedirectURIs: []string{"https://client.example/b", "https://client.example/a"}, Source: "dcr"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.RegisterClient(ClientRegistration{Name: "ChatGPT reconnect", RedirectURIs: []string{"https://client.example/a", "https://client.example/b"}, Source: "dcr"})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("equivalent registration created a new client: %q != %q", first.ID, second.ID)
	}
	if count, err := store.ClientCount(); err != nil || count != 1 {
		t.Fatalf("client count = %d, err = %v", count, err)
	}
}

func TestClientRegistrationLimitIsAtomic(t *testing.T) {
	now := time.Now()
	store := openTestStore(t, &now)
	var wait sync.WaitGroup
	for i := range 160 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = store.RegisterClient(ClientRegistration{Name: "client", RedirectURIs: []string{fmt.Sprintf("https://client.example/%d", i)}, Source: "dcr"})
		}()
	}
	wait.Wait()
	count, err := store.ClientCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 128 {
		t.Fatalf("client count = %d, want atomic cap 128", count)
	}
}
