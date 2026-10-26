package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

type OutgoingMessage struct {
	From, To, Cc, Bcc []string
	Subject, BodyText string
	InReplyTo         string
	References        string
}

func addrs(list []string) []*gomail.Address {
	out := make([]*gomail.Address, 0, len(list))
	for _, a := range list {
		out = append(out, &gomail.Address{Address: strings.TrimSpace(a)})
	}
	return out
}

func BuildRFC822(msg OutgoingMessage) ([]byte, error) {
	var h gomail.Header
	h.SetAddressList("From", addrs(msg.From))
	h.SetAddressList("To", addrs(msg.To))
	if len(msg.Cc) > 0 {
		h.SetAddressList("Cc", addrs(msg.Cc))
	}
	h.SetSubject(msg.Subject)
	h.SetDate(fixedNow())
	if msg.InReplyTo != "" {
		h.Set("In-Reply-To", msg.InReplyTo)
	}
	if msg.References != "" {
		h.Set("References", msg.References)
	}

	var buf bytes.Buffer
	mw, err := gomail.CreateWriter(&buf, h)
	if err != nil {
		return nil, err
	}
	var ih gomail.InlineHeader
	ih.Set("Content-Type", "text/plain; charset=utf-8")
	iw, err := mw.CreateSingleInline(ih)
	if err != nil {
		return nil, err
	}
	if _, err := iw.Write([]byte(msg.BodyText)); err != nil {
		return nil, err
	}
	iw.Close()
	mw.Close()
	return buf.Bytes(), nil
}

// fixedNow is overridable in tests; production uses time.Now.
var fixedNow = time.Now

type Sender struct {
	cfg       *Config
	creds     *Credentials
	dial      func(string, string) (net.Conn, error)
	tlsConfig *tls.Config
}

func NewSender(cfg *Config, creds *Credentials) *Sender { return &Sender{cfg: cfg, creds: creds} }

func (s *Sender) smtpForIdentity(fromEmail string) (*SMTPServer, *Identity, *Account, error) {
	for i := range s.cfg.Accounts {
		a := &s.cfg.Accounts[i]
		for j := range a.Identities {
			id := &a.Identities[j]
			if strings.EqualFold(id.Email, fromEmail) {
				key := id.SMTPKey
				if key == "" {
					return nil, nil, nil, fmt.Errorf("identity %s has no SMTP server configured", fromEmail)
				}
				srv, ok := s.cfg.SMTP[key]
				if !ok {
					return nil, nil, nil, fmt.Errorf("SMTP server %q not found for %s", key, fromEmail)
				}
				return &srv, id, a, nil
			}
		}
	}
	return nil, nil, nil, fmt.Errorf("no identity matches From address %q", fromEmail)
}

func (s *Sender) Send(msg OutgoingMessage) error {
	if len(msg.From) == 0 {
		return fmt.Errorf("From is required")
	}
	srv, _, _, err := s.smtpForIdentity(msg.From[0])
	if err != nil {
		return err
	}
	var auth sasl.Client
	if srv.AuthMethod == 10 {
		if srv.SocketType != 2 && srv.SocketType != 3 {
			return fmt.Errorf("OAuth2 requires TLS or STARTTLS")
		}
		token, err := s.creds.gmailAccessToken(srv.Hostname, srv.Username)
		if err != nil {
			return err
		}
		auth = &xoauth2Client{user: srv.Username, token: token}
	} else {
		pw, ok := s.creds.Lookup(srv.Hostname, srv.Username)
		if !ok {
			return fmt.Errorf("no stored password for SMTP %s@%s", srv.Username, srv.Hostname)
		}
		auth = sasl.NewPlainClient("", srv.Username, pw)
	}
	raw, err := BuildRFC822(msg)
	if err != nil {
		return err
	}
	rcpts := append(append(append([]string{}, msg.To...), msg.Cc...), msg.Bcc...)
	addr := net.JoinHostPort(srv.Hostname, strconv.Itoa(srv.Port))
	tlsConf := &tls.Config{ServerName: srv.Hostname}

	if srv.SocketType == 0 { // plaintext (loopback test server / plain local relay)
		c, err := smtp.Dial(addr)
		if err != nil {
			return err
		}
		defer c.Close()
		if err := c.SendMail(msg.From[0], rcpts, bytes.NewReader(raw)); err != nil {
			return err
		}
		return c.Quit()
	}
	if s.tlsConfig != nil {
		tlsConf = s.tlsConfig
	}
	var c *smtp.Client
	if s.dial != nil {
		conn, e := s.dial("tcp", addr)
		if e != nil {
			return e
		}
		if srv.SocketType == 3 {
			c = smtp.NewClient(tls.Client(conn, tlsConf))
		} else {
			c, err = smtp.NewClientStartTLS(conn, tlsConf)
		}
	} else if srv.SocketType == 3 {
		c, err = smtp.DialTLS(addr, tlsConf)
	} else {
		c, err = smtp.DialStartTLS(addr, tlsConf)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Auth(auth); err != nil {
		if srv.AuthMethod == 10 {
			return fmt.Errorf("Gmail SMTP OAuth2 authentication rejected; sign in again in Thunderbird")
		}
		return err
	}
	if x, ok := auth.(*xoauth2Client); ok && x.challenged {
		return fmt.Errorf("Gmail SMTP OAuth2 authentication rejected")
	}
	if err := c.SendMail(msg.From[0], rcpts, bytes.NewReader(raw)); err != nil {
		return err
	}
	return c.Quit()
}

func quoteForReply(orig MessageDetail) string {
	var b strings.Builder
	fmt.Fprintf(&b, "On %s, %s wrote:\n", orig.Date.Format("2006-01-02 15:04"), orig.Author)
	for _, line := range strings.Split(orig.BodyText, "\n") {
		b.WriteString("> " + line + "\n")
	}
	return b.String()
}

func replyHeaders(orig MessageDetail) (inReplyTo, references string) {
	inReplyTo = orig.MessageID
	references = strings.TrimSpace(orig.References + " " + orig.MessageID)
	return
}
