package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Thunderbird's built-in Google registration, not an application secret.
// See docs/configuration.md for source and compatibility constraints.
const (
	googleOrigin        = "oauth://accounts.google.com"
	googleMailScope     = "https://mail.google.com/"
	googleTokenEndpoint = "https://www.googleapis.com/oauth2/v3/token"
	googleClientID      = "406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com"
	googleClientSecret  = "kSmqreRr0qwBWJgbf5Y-PjSU"
)

type oauthLogin struct{ Origin, Username, Realm, RefreshToken string }
type oauthToken struct {
	access, refresh string
	expires         time.Time
}

func hasMailScope(scopes string) bool {
	for _, scope := range strings.Fields(scopes) {
		if scope == googleMailScope {
			return true
		}
	}
	return false
}
func gmailHost(host string) bool {
	switch strings.ToLower(host) {
	case "imap.gmail.com", "smtp.gmail.com", "imap.googlemail.com", "smtp.googlemail.com", "smtp-relay.gmail.com":
		return true
	}
	return false
}

var errOAuthGrant = errors.New("Gmail OAuth2 grant unavailable or rejected; sign in again in Thunderbird with mail access, then restart this server (custom OAuth client registrations are unsupported)")

// gmailAccessToken shares access and rotated refresh tokens across IMAP and SMTP.
// The lock also coalesces refreshes. No credential or response enters an error.
func (c *Credentials) gmailAccessToken(host, user string) (string, error) {
	if !gmailHost(host) {
		return "", errors.New("OAuth2 provider unsupported; only built-in Thunderbird Gmail grants are supported")
	}
	if c == nil || !safeSASLValue(user) {
		return "", errOAuthGrant
	}
	c.oauthMu.Lock()
	defer c.oauthMu.Unlock()
	index := -1
	for i, l := range c.oauth {
		if l.Origin == googleOrigin && l.Username == user && hasMailScope(l.Realm) && l.RefreshToken != "" {
			index = i
			break
		}
	}
	if index < 0 {
		return "", errOAuthGrant
	}
	now := time.Now()
	if c.oauthNow != nil {
		now = c.oauthNow()
	}
	if c.oauthCache == nil {
		c.oauthCache = make(map[int]*oauthToken)
	}
	token := c.oauthCache[index]
	if token == nil {
		token = &oauthToken{refresh: c.oauth[index].RefreshToken}
		c.oauthCache[index] = token
	}
	if token.access != "" && now.Add(time.Minute).Before(token.expires) {
		return token.access, nil
	}
	form := url.Values{"client_id": {googleClientID}, "client_secret": {googleClientSecret}, "grant_type": {"refresh_token"}, "refresh_token": {token.refresh}}
	req, err := http.NewRequest(http.MethodPost, googleTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errOAuthGrant
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 15 * time.Second, Transport: c.oauthTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", errOAuthGrant
	}
	defer resp.Body.Close()
	const maxBody = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody || resp.StatusCode != http.StatusOK {
		return "", errOAuthGrant
	}
	var result struct {
		Access  string  `json:"access_token"`
		Refresh string  `json:"refresh_token"`
		Type    string  `json:"token_type"`
		Expires int64   `json:"expires_in"`
		Scope   *string `json:"scope"`
	}
	if json.Unmarshal(body, &result) != nil || !safeSASLValue(result.Access) || !strings.EqualFold(result.Type, "Bearer") || result.Expires <= 60 || result.Expires > 86400*365 || result.Scope != nil && !hasMailScope(*result.Scope) {
		return "", errOAuthGrant
	}
	token.access = result.Access
	token.expires = now.Add(time.Duration(result.Expires) * time.Second)
	if result.Refresh != "" {
		token.refresh = result.Refresh
	}
	return token.access, nil
}
func safeSASLValue(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// XOAUTH2 is distinct from RFC 7628 OAUTHBEARER. An error challenge must
// receive an empty response before the server sends its final failure.
type xoauth2Client struct {
	user, token string
	challenged  bool
}

func (c *xoauth2Client) Start() (string, []byte, error) {
	if !safeSASLValue(c.user) || !safeSASLValue(c.token) {
		return "", nil, errors.New("invalid OAuth2 SASL credentials")
	}
	return "XOAUTH2", []byte("user=" + c.user + "\x01auth=Bearer " + c.token + "\x01\x01"), nil
}
func (c *xoauth2Client) Next([]byte) ([]byte, error) {
	if c.challenged {
		return nil, errors.New("OAuth2 authentication rejected")
	}
	c.challenged = true
	return []byte{}, nil
}
