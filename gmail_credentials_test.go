package main

import (
	"encoding/json"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os"
	"path/filepath"
)

var _ = Describe("OAuth credential isolation", func() {
	It("never exposes an OAuth refresh token as a password", func() {
		dir := GinkgoT().TempDir()
		writeNSSFixture(dir, "")
		data, _ := json.Marshal(map[string]any{"logins": []map[string]string{
			{"hostname": "oauth://accounts.google.com", "httpRealm": "https://mail.google.com/", "encryptedUsername": buildLogin(fxMasterKey, "alice@example.com"), "encryptedPassword": buildLogin(fxMasterKey, "synthetic-refresh")},
			{"hostname": "oauth://accounts.google.com", "httpRealm": "calendar", "encryptedUsername": buildLogin(fxMasterKey, "alice@example.com"), "encryptedPassword": buildLogin(fxMasterKey, "calendar-refresh")},
			{"hostname": "oauth://accounts.google.com", "httpRealm": "https://mail.google.com/ extra", "encryptedUsername": buildLogin(fxMasterKey, "bob@example.com"), "encryptedPassword": buildLogin(fxMasterKey, "bob-refresh")},
			{"hostname": "imap://imap.example.com", "encryptedUsername": buildLogin(fxMasterKey, "alice@example.com"), "encryptedPassword": buildLogin(fxMasterKey, "password")},
		}})
		Expect(os.WriteFile(filepath.Join(dir, "logins.json"), data, 0600)).To(Succeed())
		c, err := LoadCredentials(dir)
		Expect(err).NotTo(HaveOccurred())
		_, ok := c.Lookup("accounts.google.com", "alice@example.com")
		Expect(ok).To(BeFalse())
		Expect(c.oauth).To(Equal([]oauthLogin{
			{Origin: googleOrigin, Username: "alice@example.com", Realm: googleMailScope, RefreshToken: "synthetic-refresh"},
			{Origin: googleOrigin, Username: "alice@example.com", Realm: "calendar", RefreshToken: "calendar-refresh"},
			{Origin: googleOrigin, Username: "bob@example.com", Realm: googleMailScope + " extra", RefreshToken: "bob-refresh"},
		}))
		password, ok := c.Lookup("imap.example.com", "alice@example.com")
		Expect(ok).To(BeTrue())
		Expect(password).To(Equal("password"))
	})
})
