package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func resultText(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

func hasBlob(r *mcp.CallToolResult) bool {
	for _, c := range r.Content {
		if _, ok := c.(*mcp.EmbeddedResource); ok {
			return true
		}
	}
	return false
}

var _ = Describe("saveAttachment", func() {
	var dir string
	BeforeEach(func() { dir = GinkgoT().TempDir() })

	It("saves with mode 0600 in a per-message subdirectory", func() {
		p, err := saveAttachment(dir, "imap://h/INBOX#1", 0, "report.txt", []byte("hi"))
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.IsAbs(p)).To(BeTrue())
		Expect(filepath.Dir(filepath.Dir(p))).To(Equal(dir))
		st, err := os.Stat(p)
		Expect(err).NotTo(HaveOccurred())
		Expect(st.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		b, _ := os.ReadFile(p)
		Expect(string(b)).To(Equal("hi"))
	})

	It("keeps a traversal filename inside the directory", func() {
		for _, name := range []string{"../../evil.txt", "/etc/passwd", `..\..\evil.txt`, "..", ".", "", ".hidden"} {
			p, err := saveAttachment(dir, "ref", 3, name, []byte("x"))
			Expect(err).NotTo(HaveOccurred(), name)
			rel, err := filepath.Rel(dir, p)
			Expect(err).NotTo(HaveOccurred())
			Expect(rel).NotTo(HavePrefix(".."), name)
			Expect(strings.Count(rel, string(filepath.Separator))).To(Equal(1), name)
		}
	})

	It("does not overwrite an existing file", func() {
		p1, err := saveAttachment(dir, "ref", 0, "a.txt", []byte("one"))
		Expect(err).NotTo(HaveOccurred())
		p2, err := saveAttachment(dir, "ref", 0, "a.txt", []byte("two"))
		Expect(err).NotTo(HaveOccurred())
		Expect(p2).NotTo(Equal(p1))
		Expect(filepath.Base(p2)).To(Equal("a-1.txt"))
		b, _ := os.ReadFile(p1)
		Expect(string(b)).To(Equal("one"))
	})

	It("does not follow a planted symlink", func() {
		target := filepath.Join(GinkgoT().TempDir(), "target")
		Expect(os.WriteFile(target, []byte("keep"), 0o600)).To(Succeed())
		sub := filepath.Join(dir, messageSubdir("ref"))
		Expect(os.MkdirAll(sub, 0o700)).To(Succeed())
		Expect(os.Symlink(target, filepath.Join(sub, "a.txt"))).To(Succeed())
		p, err := saveAttachment(dir, "ref", 0, "a.txt", []byte("new"))
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.Base(p)).To(Equal("a-1.txt"))
		b, _ := os.ReadFile(target)
		Expect(string(b)).To(Equal("keep"))
	})
})

var _ = Describe("attachment size limit", func() {
	It("rejects an attachment above the limit", func() {
		raw := "From: a@example.com\r\nMIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
			"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"big.txt\"\r\n\r\n" +
			strings.Repeat("x", 100) + "\r\n--b--\r\n"
		_, _, _, err := ExtractAttachment([]byte(raw), 0, 10)
		Expect(err).To(MatchError(ContainSubstring("exceeds size limit")))
	})
})

var _ = Describe("buildAttachmentResult", func() {
	BeforeEach(func() {
		os.Setenv("THUNDERBIRD_ATTACHMENT_DIR", GinkgoT().TempDir())
		DeferCleanup(os.Unsetenv, "THUNDERBIRD_ATTACHMENT_DIR")
	})
	f := false
	t := true

	It("saves by default and reports the path", func() {
		r, err := buildAttachmentResult(GetAttachmentInput{MessageRef: "ref", Index: 0}, "", "a.bin", "application/octet-stream", []byte{1, 2, 3})
		Expect(err).NotTo(HaveOccurred())
		txt := resultText(r)
		Expect(txt).To(ContainSubstring("Saved to: " + os.Getenv("THUNDERBIRD_ATTACHMENT_DIR")))
		Expect(txt).To(ContainSubstring("application/octet-stream"))
		Expect(txt).To(ContainSubstring("3 bytes"))
		Expect(hasBlob(r)).To(BeTrue())
	})

	It("omits the blob for a large saved file", func() {
		r, err := buildAttachmentResult(GetAttachmentInput{MessageRef: "ref"}, "", "a.bin", "application/octet-stream", make([]byte, maxEmbedBytes+1))
		Expect(err).NotTo(HaveOccurred())
		Expect(hasBlob(r)).To(BeFalse())
	})

	It("keeps the blob and writes nothing when save is false", func() {
		r, err := buildAttachmentResult(GetAttachmentInput{MessageRef: "ref", Save: &f}, "", "a.bin", "application/octet-stream", make([]byte, maxEmbedBytes+1))
		Expect(err).NotTo(HaveOccurred())
		Expect(hasBlob(r)).To(BeTrue())
		Expect(resultText(r)).To(ContainSubstring("Not saved"))
		entries, _ := os.ReadDir(os.Getenv("THUNDERBIRD_ATTACHMENT_DIR"))
		Expect(entries).To(BeEmpty())
	})

	It("returns text inline", func() {
		r, err := buildAttachmentResult(GetAttachmentInput{MessageRef: "ref", Save: &t}, "", "n.csv", "text/csv; charset=utf-8", []byte("a,b\n1,2\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(resultText(r)).To(ContainSubstring("a,b\n1,2"))
		Expect(resultText(r)).NotTo(ContainSubstring("truncated"))
	})

	It("truncates long text with a note", func() {
		r, err := buildAttachmentResult(GetAttachmentInput{MessageRef: "ref"}, "", "n.txt", "text/plain", []byte(strings.Repeat("é", maxInlineTextBytes)))
		Expect(err).NotTo(HaveOccurred())
		txt := resultText(r)
		Expect(txt).To(ContainSubstring("truncated"))
		Expect(txt).To(ContainSubstring("saved file"))
		Expect(len(txt)).To(BeNumerically("<", maxInlineTextBytes+1024))
	})

	It("does not inline binary content", func() {
		r, err := buildAttachmentResult(GetAttachmentInput{MessageRef: "ref"}, "", "a.png", "image/png", []byte("PNGDATA"))
		Expect(err).NotTo(HaveOccurred())
		Expect(resultText(r)).NotTo(ContainSubstring("PNGDATA"))
	})

	It("rejects a bad index", func() {
		_, err := GetAttachment(nil, nil, GetAttachmentInput{MessageRef: "imap://h/INBOX#1", Index: -2})
		Expect(err).To(HaveOccurred())
		_, _, _, err = ExtractAttachment([]byte("Subject: x\r\n\r\nbody\r\n"), 4, 100)
		Expect(err).To(MatchError(ContainSubstring("not found")))
	})
})

var _ = Describe("shouldSave", func() {
	It("defaults on for stdio, off over HTTP without a dir", func() {
		os.Unsetenv("THUNDERBIRD_ATTACHMENT_DIR")
		Expect(shouldSave(nil)).To(BeTrue())
		servingHTTP = true
		DeferCleanup(func() { servingHTTP = false; os.Unsetenv("THUNDERBIRD_ATTACHMENT_DIR") })
		Expect(shouldSave(nil)).To(BeFalse())
		os.Setenv("THUNDERBIRD_ATTACHMENT_DIR", "/x")
		Expect(shouldSave(nil)).To(BeTrue())
		t := true
		os.Unsetenv("THUNDERBIRD_ATTACHMENT_DIR")
		Expect(shouldSave(&t)).To(BeTrue())
	})
})

var _ = Describe("attachment download route", func() {
	const bearer = "main-bearer-token-0123456789"
	const mref = "mailbox://nobody@Local%20Folders/INBOX#0"
	var h http.Handler
	var mboxMsg string

	BeforeEach(func() {
		mboxMsg = "From - Mon Jan 1\r\nFrom: a@example.com\r\nMIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
			"Content-Type: text/plain\r\n\r\nbody\r\n--b\r\n" +
			"Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"../r.pdf\"\r\n\r\n" +
			"PDFBYTES\r\n--b--\r\n"
		root := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(root, "INBOX"), []byte(mboxMsg), 0o600)).To(Succeed())
		app = &App{Config: &Config{ProfileDir: root, Accounts: []Account{{Key: "a", Type: "none", Hostname: "Local Folders", Username: "nobody", Directory: root}}}}
		app.IMAP = NewIMAP(app.Config, &Credentials{})
		setAttachmentURLKey(bearer)
		DeferCleanup(func() { attachmentURLKey = nil })
		h = newHTTPHandler(mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil), bearer)
	})

	get := func(rawURL string, hdr ...string) *httptest.ResponseRecorder {
		u, _ := url.Parse(rawURL)
		req := httptest.NewRequest("GET", u.RequestURI(), nil)
		req.Host = "127.0.0.1:1"
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	It("builds URLs from THUNDERBIRD_PUBLIC_URL or the host", func() {
		Expect(attachmentDownloadURL("h:1", mref, 0, "r.pdf")).To(HavePrefix("http://h:1/attachments/0/r.pdf?"))
		os.Setenv("THUNDERBIRD_PUBLIC_URL", "https://mail.example.org/")
		DeferCleanup(os.Unsetenv, "THUNDERBIRD_PUBLIC_URL")
		Expect(attachmentDownloadURL("h:1", mref, 0, "r.pdf")).To(HavePrefix("https://mail.example.org/attachments/0/r.pdf?"))
	})

	It("is not offered when no key is set", func() {
		attachmentURLKey = nil
		Expect(attachmentDownloadURL("h", mref, 0, "r.pdf")).To(BeEmpty())
	})

	// The mbox reader needs a real offset; keep the test on the signature layer
	// when the fixture cannot be resolved, and on the full path when it can.
	valid := func() string { return attachmentDownloadURL("127.0.0.1:1", mref, 0, "r.pdf") }

	It("rejects a missing token", func() {
		Expect(get("/attachments/0/r.pdf?ref=" + url.QueryEscape(mref)).Code).To(Equal(http.StatusForbidden))
	})

	It("rejects the main bearer token in the query or header", func() {
		Expect(get("/attachments/0/r.pdf?ref=" + url.QueryEscape(mref) + "&exp=9999999999&sig=" + bearer).Code).To(Equal(http.StatusForbidden))
		Expect(get("/attachments/0/r.pdf?ref="+url.QueryEscape(mref)+"&token="+bearer, "Authorization", "Bearer "+bearer).Code).To(Equal(http.StatusForbidden))
	})

	It("rejects a tampered signature", func() {
		u := valid()
		Expect(get(u[:len(u)-2] + "00").Code).To(Equal(http.StatusForbidden))
	})

	It("rejects another index or message", func() {
		u := valid()
		Expect(get(strings.Replace(u, "/attachments/0/", "/attachments/1/", 1)).Code).To(Equal(http.StatusForbidden))
		other := strings.Replace(u, url.QueryEscape(mref), url.QueryEscape("mailbox://nobody@Local%20Folders/INBOX#9"), 1)
		Expect(other).NotTo(Equal(u))
		Expect(get(other).Code).To(Equal(http.StatusForbidden))
	})

	It("rejects an expired token", func() {
		os.Setenv("THUNDERBIRD_ATTACHMENT_URL_TTL", "1ms")
		DeferCleanup(os.Unsetenv, "THUNDERBIRD_ATTACHMENT_URL_TTL")
		// exp is in whole seconds, so sign one in the past explicitly.
		exp := time.Now().Add(-time.Minute).Unix()
		u := "/attachments/0/r.pdf?ref=" + url.QueryEscape(mref) + "&exp=" + itoa(exp) + "&sig=" + signAttachment(mref, 0, exp)
		Expect(get(u).Code).To(Equal(http.StatusForbidden))
	})

	It("streams the file with attachment headers for a valid token", func() {
		w := get(valid())
		Expect(w.Code).To(Equal(http.StatusOK), w.Body.String())
		Expect(w.Header().Get("Content-Type")).To(Equal("application/pdf"))
		cd := w.Header().Get("Content-Disposition")
		Expect(cd).To(HavePrefix("attachment"))
		Expect(cd).NotTo(ContainSubstring(".."))
		Expect(w.Body.String()).To(ContainSubstring("PDFBYTES"))
	})

	It("honours the configured TTL", func() {
		Expect(attachmentURLTTL()).To(Equal(10 * time.Minute))
		os.Setenv("THUNDERBIRD_ATTACHMENT_URL_TTL", "30s")
		DeferCleanup(os.Unsetenv, "THUNDERBIRD_ATTACHMENT_URL_TTL")
		Expect(attachmentURLTTL()).To(Equal(30 * time.Second))
	})
})

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

var _ = Describe("ParseMessage attachment list", func() {
	It("numbers each attachment with the index get_attachment expects", func() {
		raw := "From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n" +
			"--b\r\nContent-Type: text/csv\r\nContent-Disposition: attachment; filename=\"a.csv\"\r\n\r\n1,2\r\n" +
			"--b\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"b.png\"\r\n\r\nPNG\r\n--b--\r\n"
		d, err := ParseMessage("imap://h/INBOX#1", []byte(raw))
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Attachments).To(HaveLen(2))
		Expect(d.Attachments[1].Index).To(Equal(1))
		Expect(d.Attachments[1].Filename).To(Equal("b.png"))
		Expect(d.Attachments[1].ContentType).To(Equal("image/png"))
		Expect(d.Attachments[1].Size).To(BeNumerically(">", 0))
	})
})
