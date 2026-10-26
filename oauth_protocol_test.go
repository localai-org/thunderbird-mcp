package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Route only the mail socket to a synthetic TLS server; retain production host
// and TLS verification, including ServerName. Never dial a public mail host.
func protocolTLS(t *testing.T, startTLS bool) (net.Listener, *tls.Config, *tls.Config) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if !startTLS && err == nil {
		ln = tls.NewListener(ln, s.TLS)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, &tls.Config{RootCAs: s.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, ServerName: "example.com"}, s.TLS
}
func TestOAuthProtocols(t *testing.T) {
	for _, protocol := range []string{"imap", "smtp"} {
		for _, mode := range []string{"implicit-ir", "implicit-noir", "starttls", "starttls-reject"} {
			for _, user := range []string{"alice@example.com", "bob@example.com"} {
				for _, reject := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/reject=%v", protocol, mode, user, reject), func(t *testing.T) {
						startTLS := strings.HasPrefix(mode, "starttls")
						ln, tlsConf, serverTLS := protocolTLS(t, startTLS)
						socketType := 3
						if startTLS {
							socketType = 2
						}
						done := make(chan error, 1)
						go func() {
							conn, err := ln.Accept()
							if err != nil {
								done <- err
								return
							}
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(5 * time.Second))
							r := bufio.NewReader(conn)
							write := func(s string) { fmt.Fprint(conn, s+"\r\n") }
							read := func() string {
								s, e := r.ReadString('\n')
								if e != nil {
									err = e
								}
								return strings.TrimRight(s, "\r\n")
							}
							checkPayload := func(payload string) {
								b, e := base64.StdEncoding.DecodeString(payload)
								if e != nil || string(b) != "user="+user+"\x01auth=Bearer access\x01\x01" {
									err = fmt.Errorf("wrong XOAUTH2 payload")
								}
							}
							if startTLS {
								if protocol == "imap" {
									write("* OK [CAPABILITY IMAP4rev1 STARTTLS] ready")
									p := strings.Fields(read())
									if len(p) != 2 || p[1] != "STARTTLS" {
										done <- fmt.Errorf("authentication before STARTTLS")
										return
									}
									if mode == "starttls-reject" {
										write(p[0] + " NO upgrade refused")
										done <- err
										return
									}
									write(p[0] + " OK begin TLS")
								} else {
									write("220 localhost ESMTP")
									if !strings.HasPrefix(read(), "EHLO ") {
										done <- fmt.Errorf("no EHLO before STARTTLS")
										return
									}
									write("250-localhost")
									write("250 STARTTLS")
									if read() != "STARTTLS" {
										done <- fmt.Errorf("authentication before STARTTLS")
										return
									}
									if mode == "starttls-reject" {
										write("454 upgrade refused")
										done <- err
										return
									}
									write("220 begin TLS")
								}
								secure := tls.Server(conn, serverTLS)
								if e := secure.Handshake(); e != nil {
									done <- e
									return
								}
								conn = secure
								r = bufio.NewReader(conn)
							}
							if protocol == "imap" {
								if !startTLS {
									caps := "IMAP4rev1 AUTH=XOAUTH2"
									if mode != "implicit-noir" {
										caps += " SASL-IR"
									}
									write("* OK [CAPABILITY " + caps + "] ready")
								}
								line := read()
								if startTLS {
									p := strings.Fields(line)
									if len(p) != 2 || p[1] != "CAPABILITY" {
										done <- fmt.Errorf("no post-TLS CAPABILITY")
										return
									}
									write("* CAPABILITY IMAP4rev1 AUTH=XOAUTH2 SASL-IR")
									write(p[0] + " OK capability")
									line = read()
								}
								parts := strings.Fields(line)
								if len(parts) < 3 || parts[1] != "AUTHENTICATE" || parts[2] != "XOAUTH2" {
									done <- fmt.Errorf("not XOAUTH2: %s", line)
									return
								}
								tag := parts[0]
								if len(parts) == 4 {
									checkPayload(parts[3])
								} else {
									write("+ ")
									checkPayload(read())
								}
								if reject {
									write("+ " + base64.StdEncoding.EncodeToString([]byte(`{"status":"401","private":"PRIVATE"}`)))
									ack := read()
									if ack != "=" && ack != "" {
										err = fmt.Errorf("wrong error acknowledgement")
									}
									write(tag + " NO PRIVATE")
								} else {
									write(tag + " OK authenticated")
								}
							} else {
								if !startTLS {
									write("220 localhost ESMTP")
								}
								if !strings.HasPrefix(read(), "EHLO ") {
									err = fmt.Errorf("no EHLO")
								}
								write("250-localhost")
								write("250 AUTH XOAUTH2")
								p := strings.Fields(read())
								if len(p) != 3 || p[0] != "AUTH" || p[1] != "XOAUTH2" {
									done <- fmt.Errorf("not XOAUTH2")
									return
								}
								checkPayload(p[2])
								if reject {
									write("334 " + base64.StdEncoding.EncodeToString([]byte(`{"status":"401","private":"PRIVATE"}`)))
									if read() != "" {
										err = fmt.Errorf("wrong error acknowledgement")
									}
									write("535 PRIVATE")
									if read() == "*" {
										write("501 aborted")
									}
								} else {
									write("235 authenticated")
									if !strings.HasPrefix(read(), "MAIL FROM:") {
										err = fmt.Errorf("no MAIL")
									}
									write("250 OK")
									if !strings.HasPrefix(read(), "RCPT TO:") {
										err = fmt.Errorf("no RCPT")
									}
									write("250 OK")
									if read() != "DATA" {
										err = fmt.Errorf("no DATA")
									}
									write("354 data")
									for read() != "." && err == nil {
									}
									write("250 OK")
									if read() != "QUIT" {
										err = fmt.Errorf("no QUIT")
									}
									write("221 bye")
								}
							}
							done <- err
						}()
						c := oauthFixture()
						c.oauth = append(c.oauth, oauthLogin{Origin: googleOrigin, Username: "bob@example.com", Realm: googleMailScope, RefreshToken: "bob-refresh"})
						c.oauthTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
							return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"access","expires_in":3600,"token_type":"Bearer"}`))}, nil
						})
						dial := func(_ string, _ string) (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) }
						var err error
						if protocol == "imap" {
							m := NewIMAP(&Config{}, c)
							m.dial = dial
							m.tlsConfig = tlsConf
							var client io.Closer
							client, err = m.connect(&Account{Hostname: "imap.gmail.com", Port: 993, Username: user, AuthMethod: 10, SocketType: socketType})
							if err == nil {
								client.Close()
							}
						} else {
							_, p, _ := net.SplitHostPort(ln.Addr().String())
							port, _ := strconv.Atoi(p)
							s := NewSender(&Config{Accounts: []Account{{Identities: []Identity{{Email: user, SMTPKey: "s"}}}}, SMTP: map[string]SMTPServer{"s": {Hostname: "smtp.gmail.com", Username: user, Port: port, AuthMethod: 10, SocketType: socketType}}}, c)
							s.dial = dial
							s.tlsConfig = tlsConf
							err = s.Send(OutgoingMessage{From: []string{user}, To: []string{"recipient@example.com"}, BodyText: "synthetic"})
						}
						if reject || mode == "starttls-reject" {
							if err == nil || strings.Contains(err.Error(), "PRIVATE") {
								t.Errorf("unsafe auth error: %v", err)
							}
						} else if err != nil {
							t.Error(err)
						}
						select {
						case e := <-done:
							if e != nil {
								t.Error(e)
							}
						case <-time.After(6 * time.Second):
							t.Error("protocol timeout")
						}
					})
				}
			}
		}
	}
}

func TestOAuthPlaintextRejected(t *testing.T) {
	c := oauthFixture()
	c.oauthTransport = roundTripFunc(func(*http.Request) (*http.Response, error) { t.Error("refresh on plaintext path"); return nil, io.EOF })
	dial := func(string, string) (net.Conn, error) { t.Error("dial on plaintext path"); return nil, io.EOF }
	for _, socket := range []int{0, 1} {
		m := NewIMAP(&Config{}, c)
		m.dial = dial
		if _, err := m.connect(&Account{Hostname: "imap.gmail.com", Username: "alice@example.com", AuthMethod: 10, SocketType: socket}); err == nil {
			t.Error("plaintext IMAP allowed")
		}
		s := NewSender(&Config{Accounts: []Account{{Identities: []Identity{{Email: "alice@example.com", SMTPKey: "s"}}}}, SMTP: map[string]SMTPServer{"s": {Hostname: "smtp.gmail.com", Username: "alice@example.com", AuthMethod: 10, SocketType: socket}}}, c)
		s.dial = dial
		if err := s.Send(OutgoingMessage{From: []string{"alice@example.com"}, To: []string{"recipient@example.com"}}); err == nil {
			t.Error("plaintext SMTP allowed")
		}
	}
}
