package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

// App holds all runtime state for the Thunderbird MCP server.
type App struct {
	Config    *Config
	ReadOnly  bool
	AllowSend bool

	Gloda       *Gloda
	Contacts    *Contacts
	Calendar    *Calendar
	calendarErr error // retain startup storage failures for list_events
	IMAP        *IMAP
	Sender      *Sender
}

// app is the process-wide server state, populated in main().
var app *App

// LoadApp discovers/loads the profile and opens every data source.
func LoadApp(profileDir string, readOnly, allowSend bool) (*App, error) {
	cfg, err := loadProfile(profileDir)
	if err != nil {
		return nil, err
	}
	creds, err := LoadCredentials(profileDir)
	if err != nil {
		// A credential/decryption failure (including ErrMasterPassword) must not be
		// fatal: it only disables IMAP/SMTP. The read-only gloda/contacts/calendar/local
		// tools need no credentials, so continue with an empty credential store — its
		// Lookup returns ("", false), so IMAP.connect/Sender.Send fail cleanly later.
		log.Printf("thunderbird: WARNING: could not load credentials (%v); IMAP/SMTP (fetch, mutate, send) disabled — read-only search/contacts/calendar still available", err)
		creds = &Credentials{}
	}
	return loadAppFromConfig(cfg, creds, readOnly, allowSend)
}

func loadAppFromConfig(cfg *Config, creds *Credentials, readOnly, allowSend bool) (*App, error) {
	a := &App{Config: cfg, ReadOnly: readOnly, AllowSend: allowSend}
	a.IMAP = NewIMAP(cfg, creds)
	a.Sender = NewSender(cfg, creds)

	if g, err := OpenGloda(cfg.ProfileDir); err != nil {
		log.Printf("thunderbird: gloda unavailable: %v", err)
	} else {
		a.Gloda = g
	}
	if c, err := OpenContacts(cfg.ProfileDir); err != nil {
		log.Printf("thunderbird: contacts unavailable: %v", err)
	} else {
		a.Contacts = c
	}
	if c, err := OpenCalendar(cfg.ProfileDir, cfg.Calendars); err != nil {
		log.Printf("thunderbird: calendar unavailable: %v", err)
		a.calendarErr = err
	} else {
		a.Calendar = c
	}
	return a, nil
}

// Close releases every data source the app opened. Its main job is deleting
// the snapshot directories dbSource creates under $TMPDIR: those hold a full
// copy of the database (gloda routinely runs to hundreds of MB) and /tmp is
// RAM-backed on most Linux systems, so leaking them across runs is expensive.
//
// Nil-safe at both levels. The app itself may be nil, and each source may be
// nil because Open* returns (nil, nil) when the profile file is absent.
func (a *App) Close() error {
	if a == nil {
		return nil
	}
	return errors.Join(a.Gloda.Close(), a.Contacts.Close(), a.Calendar.Close())
}

func (a *App) folderIsLocal(folderURI string) bool {
	return strings.HasPrefix(folderURI, "mailbox://")
}

func (a *App) localAccountFor(folderURI string) (*Account, error) {
	host := mailboxAuthorityHost(folderURI)
	var first *Account
	for i := range a.Config.Accounts {
		acct := &a.Config.Accounts[i]
		if !acct.IsLocal() {
			continue
		}
		if first == nil {
			first = acct
		}
		if host != "" && acct.Hostname == host {
			return acct, nil
		}
	}
	if first != nil {
		return first, nil
	}
	return nil, fmt.Errorf("no local account for %q", folderURI)
}

// accountFolderRoot maps a configured account key to the URI authority used by
// Thunderbird's index. An omitted key deliberately leaves the query unscoped.
func (a *App) accountFolderRoot(key string) (string, error) {
	if key == "" {
		return "", nil
	}
	for _, account := range a.Config.Accounts {
		if account.Key != key {
			continue
		}
		scheme := "imap"
		if account.IsLocal() {
			scheme = "mailbox"
		} else if account.Type != "imap" {
			return "", fmt.Errorf("unsupported account type %q", account.Type)
		}
		user := ""
		if account.Username != "" {
			user = escapeServerURI(account.Username, false) + "@"
		}
		return scheme + "://" + user + escapeServerURI(account.Hostname, true), nil
	}
	return "", fmt.Errorf("unknown account key %q (see list_accounts)", key)
}

// escapeServerURI mirrors GetServerURI's MsgEscapeString: ESCAPE_XALPHAS
// for usernames and ESCAPE_URL_PATH for hostnames, not Go's PathEscape.
// See mailnews/base/src/nsMsgIncomingServer.cpp and xpcom/io/nsEscape.cpp
// (netCharType bits 1 and 4). Percent escapes operate on UTF-8 bytes.
func escapeServerURI(s string, host bool) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("*-._", rune(c)) || host && (c == '+' || c == '/') {
			out.WriteByte(c)
		} else {
			out.WriteByte('%')
			out.WriteByte(hex[c>>4])
			out.WriteByte(hex[c&15])
		}
	}
	return out.String()
}
