package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/domain"
	"forge.cadoles.com/rmasson/hydra-dispatcher-go/internal/store"
)

type rehashCall struct{ id, old, new string }

// waitRehashed waits until no rehash of id runs.
func waitRehashed(t *testing.T, a *API, id string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, busy := a.rehashing.Load(id); !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rehash of %s never ends", id)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Q118: the first token granted to a client whose hash has another cost (cost
// 4 here, 13 for Symfony's) hashes its secret again, at the current cost; a
// failure leaves the token; a hash at the current cost, an unknown client or
// a wrong secret are not hashed again.
func TestTokenRehash(t *testing.T) {
	r := newRig(t)
	current, err := domain.HashSecret(clientSecret)
	if err != nil {
		t.Fatal(err)
	}
	r.config.set(
		store.APIClient{ID: clientID, SecretHash: clientHash(), Scopes: []string{ScopeFlows}},
		store.APIClient{ID: "current", SecretHash: current, Scopes: []string{ScopeRead}},
	)
	calls := make(chan rehashCall, 8)
	var fail atomic.Bool
	r.api.o.Rehash = func(_ context.Context, id, old, new string) error {
		calls <- rehashCall{id, old, new}
		if fail.Load() {
			return errors.New("the database is down")
		}
		return nil
	}
	token := func(client, secret string) int {
		return r.tokenForm(form("grant_type", "client_credentials", "client_id", client, "client_secret", secret)).Code
	}

	if code := token(clientID, clientSecret); code != http.StatusOK {
		t.Fatalf("token: %d", code)
	}
	select {
	case c := <-calls:
		cost, _ := bcrypt.Cost([]byte(c.new))
		if c.id != clientID || c.old != clientHash() || cost != bcrypt.DefaultCost || !domain.SecretMatches(c.new, clientSecret) {
			t.Errorf("rehash %+v, cost %d", c, cost)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no rehash")
	}
	waitRehashed(t, r.api, clientID)

	// Neither a hash at the current cost, nor an unknown client, nor a wrong
	// secret.
	if token("current", clientSecret) != http.StatusOK || token("nobody", clientSecret) != http.StatusUnauthorized || token(clientID, "wrong") != http.StatusUnauthorized {
		t.Fatal("tokens")
	}
	waitRehashed(t, r.api, "current")
	select {
	case c := <-calls:
		t.Errorf("rehash of %+v", c)
	case <-time.After(200 * time.Millisecond):
	}

	// A failure: the token stays, the log says it.
	fail.Store(true)
	if code := token(clientID, clientSecret); code != http.StatusOK {
		t.Errorf("token with a failed rehash: %d", code)
	}
	<-calls
	waitRehashed(t, r.api, clientID)
	r.mu.Lock()
	logs := r.logs.String()
	r.mu.Unlock()
	if !strings.Contains(logs, `"msg":"admin.rehash_failed"`) || !strings.Contains(logs, `"msg":"admin.secret_rehashed"`) || strings.Contains(logs, clientSecret) {
		t.Errorf("logs:\n%s", logs)
	}
}

// At most one bcrypt per processor at once: the others wait their turn
// (revue R34).
func TestTokenBcryptBounded(t *testing.T) {
	r := newRig(t)
	limit := cap(r.api.bcrypt)
	var running, most atomic.Int32
	release := make(chan struct{})
	saved := secretMatches
	secretMatches = func(hash, secret string) bool {
		n := running.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		<-release
		running.Add(-1)
		return saved(hash, secret)
	}
	t.Cleanup(func() { secretMatches = saved })
	var wg sync.WaitGroup
	for range limit + 3 {
		wg.Go(func() {
			r.tokenForm(form("grant_type", "client_credentials", "client_id", clientID, "client_secret", clientSecret))
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for running.Load() < int32(limit) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // time for a fourth to come in, were it free to
	if n := running.Load(); n != int32(limit) {
		t.Errorf("%d bcrypts at once, want %d", n, limit)
	}
	close(release)
	wg.Wait()
	if m := most.Load(); m != int32(limit) {
		t.Errorf("at most %d bcrypts at once, want %d", m, limit)
	}
}

// An object where a list is wanted is a type error, 400, not a 422 with the
// message of encoding/json: PHP calls an object an array (revue R35).
func TestObjectForAList(t *testing.T) {
	r := newResources(t)
	r.withApps("a")
	for path, body := range map[string]string{
		"/admin/v1/settings":           `{"supportedLocales": {"fr": "fr"}}`,
		"/admin/v1/apps/a":             `{"receiveClaims": {"email": true}}`,
		"/admin/v1/oauth2-clients/all": `{"scopes": {"admin:read": true}}`,
	} {
		w := r.do(r.all, http.MethodPatch, path, "application/merge-patch+json", body)
		if w.Code != http.StatusBadRequest || !strings.Contains(problemOf(t, w).Detail, `"object" given`) {
			t.Errorf("PATCH %s: %d %s", path, w.Code, w.Body)
		}
	}
}
