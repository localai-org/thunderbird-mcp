package main

import "testing"

func TestGmailFolderSelection(t *testing.T) {
	m := NewIMAP(&Config{Accounts: []Account{
		{Type: "imap", Hostname: "imap.gmail.com", Username: "first@example.com"},
		{Type: "imap", Hostname: "imap.gmail.com", Username: "second@example.com"},
	}}, &Credentials{})
	a, err := m.accountForFolderURI("imap://second%40example.com@imap.gmail.com/INBOX")
	if err != nil || a.Username != "second@example.com" {
		t.Fatalf("wrong account: %v, %v", a, err)
	}
	for _, uri := range []string{"imap://imap.gmail.com/INBOX", "imap://missing@example.com@imap.gmail.com/INBOX", "https://second%40example.com@imap.gmail.com/INBOX"} {
		if _, err := m.accountForFolderURI(uri); err == nil {
			t.Errorf("unsafe match for %s", uri)
		}
	}
}
