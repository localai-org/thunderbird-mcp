package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestEscapeServerURI(t *testing.T) {
	for _, tt := range []struct {
		input string
		host  bool
		want  string
	}{
		{"alice@example.com", false, "alice%40example.com"},
		{"a+~* -._%é", false, "a%2B%7E*%20-._%25%C3%A9"},
		{"a+~*/ -._%@é", true, "a+%7E*/%20-._%25%40%C3%A9"},
		{"", false, ""},
	} {
		if got := escapeServerURI(tt.input, tt.host); got != tt.want {
			t.Errorf("escapeServerURI(%q, %v) = %q, want %q", tt.input, tt.host, got, tt.want)
		}
	}
}

// Entirely synthetic: no profile discovery, credentials, or network access.
func TestMailAccountFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gloda.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE folderLocations (id INTEGER PRIMARY KEY, folderURI TEXT);
 CREATE TABLE messages (id INTEGER PRIMARY KEY, folderID INTEGER, messageKey INTEGER, date INTEGER, deleted INTEGER);
 CREATE TABLE messagesText_content (docid INTEGER PRIMARY KEY, c0body TEXT, c1subject TEXT, c3author TEXT, c4recipients TEXT);`)
	if err != nil {
		t.Fatal(err)
	}
	accounts := []Account{
		{Key: "account1", Type: "imap", Username: "alice", Hostname: "example.com"},
		{Key: "account2", Type: "imap", Username: "bob", Hostname: "example.com"},
		{Key: "local", Type: "none", Username: "nobody", Hostname: "Local Folders"},
		{Key: "pop", Type: "pop3", Username: "pop", Hostname: "pop.example.com"},
		{Key: "escaped", Type: "imap", Username: "a_%", Hostname: "example.com"},
		{Key: "email", Type: "imap", Username: "alice@example.com", Hostname: "imap.example.com"},
		{Key: "special", Type: "imap", Username: "a+~*", Hostname: "imap.example.com"},
		{Key: "anonymous", Type: "imap", Hostname: "imap.example.com"},
		{Key: "empty", Type: "imap", Username: "empty", Hostname: "example.com"},
	}
	roots := []string{"imap://alice@example.com", "imap://bob@example.com", "mailbox://nobody@Local%20Folders", "mailbox://pop@pop.example.com", "imap://a_%25@example.com", "imap://alice%40example.com@imap.example.com", "imap://a%2B%7E*@imap.example.com", "imap://imap.example.com", "imap://alice@example.com.evil", "imap://aXZZ25@example.com", "imap://Alice@example.com"}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	id := 0
	for group, root := range roots {
		for folder := 0; folder < 2; folder++ {
			fid := group*2 + folder + 1
			_, err = tx.Exec("INSERT INTO folderLocations VALUES (?, ?)", fid, fmt.Sprintf("%s/folder%d", root, folder))
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < 110; n++ {
				id++
				_, err = tx.Exec("INSERT INTO messages VALUES (?, ?, ?, ?, 0)", id, fid, id, id)
				if err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec("INSERT INTO messagesText_content VALUES (?, 'needle', 'synthetic', 'sender@example.invalid', 'recipient@example.invalid')", id)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	g, err := openGlodaAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	previous := app
	app = &App{Config: &Config{Accounts: accounts}, Gloda: g}
	defer func() { app = previous }()
	for _, action := range []string{"list_recent", "search_messages"} {
		t.Run(action, func(t *testing.T) {
			call := func(account, folder string, limit, offset int) (MailOutput, error) {
				_, out, err := ThunderbirdMail(context.Background(), nil, MailInput{Action: action, Account: account, Folder: folder, Query: "needle", Limit: limit, Offset: offset})
				return out, err
			}
			for i, a := range accounts[:8] {
				t.Run(a.Key, func(t *testing.T) {
					out, err := call(a.Key, "", 200, 0)
					if err != nil {
						t.Fatal(err)
					}
					if out.Count != 200 {
						t.Fatalf("count = %d, want 200", out.Count)
					}
					if out.Messages[0].Date.UnixMicro() != int64((i+1)*220) {
						t.Fatal("did not return the newest message in the selected account")
					}
					for n, m := range out.Messages {
						if n > 0 && !out.Messages[n-1].Date.After(m.Date) {
							t.Fatal("messages are not ordered newest-first")
						}
						if !strings.HasPrefix(m.Ref, roots[i]+"/") {
							t.Fatalf("account %s returned cross-account synthetic ref %q", a.Key, m.Ref)
						}
					}
					out, err = call(a.Key, roots[i]+"/folder0", 200, 0)
					if err != nil || out.Count != 110 {
						t.Fatalf("folder intersection: count=%d err=%v", out.Count, err)
					}
				})
			}
			t.Run("unknown", func(t *testing.T) {
				out, err := call("unknown", "", 200, 0)
				if err == nil || out.Count != 0 {
					t.Fatalf("unknown account must fail closed: count=%d err=%v", out.Count, err)
				}
			})
			t.Run("empty", func(t *testing.T) {
				out, err := call("empty", "", 200, 0)
				if err != nil || out.Count != 0 {
					t.Fatalf("empty account: count=%d err=%v", out.Count, err)
				}
			})
			t.Run("conflicting-folder", func(t *testing.T) {
				out, err := call("account1", roots[1]+"/folder0", 200, 0)
				if err != nil || out.Count != 0 {
					t.Fatalf("conflicting folder: count=%d err=%v", out.Count, err)
				}
			})
			t.Run("all-accounts-and-default", func(t *testing.T) {
				out, err := call("", "", id+1, 0)
				if err != nil || out.Count != id {
					t.Fatalf("all accounts: count=%d want=%d err=%v", out.Count, id, err)
				}
				out, err = call("", "", 0, 0)
				if err != nil || out.Count != 20 {
					t.Fatalf("default: count=%d err=%v", out.Count, err)
				}
			})
			if action == "search_messages" {
				t.Run("pagination", func(t *testing.T) {
					full, err := call("account1", "", 200, 0)
					if err != nil {
						t.Fatal(err)
					}
					page, err := call("account1", "", 10, 7)
					if err != nil || page.Count != 10 {
						t.Fatalf("page: count=%d err=%v", page.Count, err)
					}
					for i, m := range page.Messages {
						if m.Ref != full.Messages[i+7].Ref {
							t.Fatal("pagination differs from scoped results")
						}
					}
				})
			}
		})
	}
}
