package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func oauthFixture() *Credentials {
	return &Credentials{oauth: []oauthLogin{{Origin: googleOrigin, Username: "alice@example.com", Realm: "other " + googleMailScope, RefreshToken: "refresh"}}}
}
func TestOAuthCacheRotation(t *testing.T) {
	c := oauthFixture()
	now := time.Now()
	calls := 0
	c.oauthNow = func() time.Time { return now }
	c.oauthTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != googleTokenEndpoint {
			t.Error("unexpected endpoint")
		}
		r.ParseForm()
		want := "refresh"
		if calls > 1 {
			want = "rotated"
		}
		if r.Form.Get("refresh_token") != want || r.Form.Get("client_id") != googleClientID || r.Form.Get("client_secret") != googleClientSecret || r.Form.Get("grant_type") != "refresh_token" {
			t.Error("wrong refresh request")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"access_token":"access","expires_in":3600,"token_type":"Bearer","refresh_token":"rotated"}`)), Header: make(http.Header)}, nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, e := c.gmailAccessToken("imap.gmail.com", "alice@example.com")
			if e != nil || s != "access" {
				t.Error("token unavailable")
			}
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("refresh calls %d", calls)
	}
	now = now.Add(time.Hour)
	if _, err := c.gmailAccessToken("smtp.gmail.com", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("not refreshed")
	}
	if c.oauth[0].RefreshToken != "refresh" {
		t.Fatal("saved credential mutated")
	}
}
func TestOAuthSelectionAndErrors(t *testing.T) {
	for _, tc := range []struct{ host, user, realm, origin string }{
		{"imap.evil.test", "alice@example.com", googleMailScope, googleOrigin},
		{"imap.gmail.com", "other@example.com", googleMailScope, googleOrigin},
		{"imap.gmail.com", "alice@example.com", googleMailScope + "evil", googleOrigin},
		{"imap.gmail.com", "alice@example.com", googleMailScope, googleOrigin + "/"},
	} {
		c := oauthFixture()
		c.oauth[0].Realm = tc.realm
		c.oauth[0].Origin = tc.origin
		if _, err := c.gmailAccessToken(tc.host, tc.user); err == nil {
			t.Error("unsafe credential selection")
		}
	}
	for _, body := range []string{`{"error":"invalid_grant","error_description":"PRIVATE"}`, `PRIVATE`, strings.Repeat("PRIVATE", 20000), `{"access_token":"PRIVATE","expires_in":0}`, `{"access_token":"PRIVATE","expires_in":3600,"token_type":"Bearer","scope":"other"}`} {
		c := oauthFixture()
		c.oauthTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 400, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		if _, err := c.gmailAccessToken("imap.gmail.com", "alice@example.com"); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
	c := oauthFixture()
	calls := 0
	c.oauthTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{"https://evil.test/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if _, err := c.gmailAccessToken("imap.gmail.com", "alice@example.com"); err == nil || calls != 1 {
		t.Fatal("redirect followed")
	}
}

func TestOAuthRejectsUnsafeUserBeforeRefresh(t *testing.T) {
	for _, user := range []string{"alice\x01@example.com", "alice\r\n@example.com", "alice\x7f@example.com", "alice\t@example.com"} {
		c := oauthFixture()
		c.oauth[0].Username = user
		calls := 0
		c.oauthTransport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, io.EOF })
		if _, err := c.gmailAccessToken("imap.gmail.com", user); err == nil {
			t.Error("unsafe user accepted")
		}
		if calls != 0 {
			t.Error("refreshed before validating user")
		}
	}
}

func TestOAuthMalformedSuccess(t *testing.T) {
	for _, body := range []string{`PRIVATE`, strings.Repeat("PRIVATE", 20000), `{"access_token":"PRIVATE","expires_in":0}`, `{"access_token":"PRIVATE","expires_in":3600,"token_type":"Bearer","scope":"other"}`, `{"access_token":"bad\u0001token","expires_in":3600,"token_type":"Bearer"}`} {
		c := oauthFixture()
		c.oauthTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		if _, err := c.gmailAccessToken("imap.gmail.com", "alice@example.com"); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Errorf("unsafe success error: %v", err)
		}
	}
}

func TestOAuthRealmAndUserIsolation(t *testing.T) {
	c := oauthFixture()
	c.oauth = []oauthLogin{
		{Origin: googleOrigin, Username: "alice@example.com", Realm: "calendar", RefreshToken: "wrong-scope"},
		{Origin: googleOrigin + "/", Username: "alice@example.com", Realm: googleMailScope, RefreshToken: "wrong-origin"},
		{Origin: googleOrigin, Username: "bob@example.com", Realm: googleMailScope, RefreshToken: "bob"},
		{Origin: googleOrigin, Username: "alice@example.com", Realm: "calendar " + googleMailScope, RefreshToken: "alice"},
	}
	calls := 0
	c.oauthTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		refresh := r.Form.Get("refresh_token")
		if refresh != "alice" && refresh != "bob" {
			t.Error("wrong grant selected")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"` + refresh + `","expires_in":3600,"token_type":"Bearer"}`))}, nil
	})
	for _, user := range []string{"alice", "bob", "alice", "bob"} {
		token, err := c.gmailAccessToken("imap.gmail.com", user+"@example.com")
		if err != nil || token != user {
			t.Errorf("cross-user selection: %q, %v", token, err)
		}
	}
	if calls != 2 {
		t.Errorf("refresh calls: %d", calls)
	}
}
