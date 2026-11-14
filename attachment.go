package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// attachmentDirName is the directory created under the user cache
	// directory when THUNDERBIRD_ATTACHMENT_DIR is not set.
	attachmentDirName = "thunderbird-mcp-attachments"

	// maxInlineTextBytes is the most decoded text returned inline for a
	// text-like attachment. Longer content is cut and a note says so.
	maxInlineTextBytes = 64 * 1024

	// maxEmbedBytes is the largest attachment that is still embedded as an
	// MCP resource blob when it was also saved to disk. Bigger files are
	// only saved, to keep the response small.
	maxEmbedBytes = 256 * 1024

	maxSavedNameBytes = 200
)

// servingHTTP is set when the server runs over HTTP. A path on the server's
// disk is useless to a remote client, so saving is then opt-in.
var servingHTTP bool

// attachmentDir returns the directory attachments are saved to and whether
// it was configured explicitly.
func attachmentDir() (dir string, explicit bool, err error) {
	if d := strings.TrimSpace(os.Getenv("THUNDERBIRD_ATTACHMENT_DIR")); d != "" {
		abs, err := filepath.Abs(d)
		return abs, true, err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", false, fmt.Errorf("no cache directory available, set THUNDERBIRD_ATTACHMENT_DIR: %w", err)
	}
	return filepath.Join(cache, attachmentDirName), false, nil
}

// shouldSave decides whether to write the attachment to disk. An explicit
// request wins. Otherwise it saves, except over HTTP without a configured
// directory.
func shouldSave(requested *bool) bool {
	if requested != nil {
		return *requested
	}
	if servingHTTP && strings.TrimSpace(os.Getenv("THUNDERBIRD_ATTACHMENT_DIR")) == "" {
		return false
	}
	return true
}

// messageSubdir names the per-message directory. It is a hash, so a message
// reference never becomes a path component.
func messageSubdir(messageRef string) string {
	sum := sha256.Sum256([]byte(messageRef))
	return hex.EncodeToString(sum[:8])
}

// safeAttachmentName turns an untrusted filename into one safe path element.
func safeAttachmentName(fn string, index int) string {
	name := SanitizeFilename(fn)
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' || r == ':' {
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	name = strings.TrimLeft(name, ".")
	if name == "" {
		name = fmt.Sprintf("attachment-%d", index)
	}
	if len(name) > maxSavedNameBytes {
		ext := filepath.Ext(name)
		if len(ext) > 20 {
			ext = ""
		}
		stem := name[:maxSavedNameBytes-len(ext)]
		for !utf8.ValidString(stem) {
			stem = stem[:len(stem)-1]
		}
		name = stem + ext
	}
	return name
}

// saveAttachment writes data below baseDir in a per-message subdirectory and
// returns the absolute path. It never overwrites: a taken name gets a
// numeric suffix. Files are created with mode 0600.
func saveAttachment(baseDir, messageRef string, index int, filename string, data []byte) (string, error) {
	dir := filepath.Join(baseDir, messageSubdir(messageRef))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating attachment directory: %w", err)
	}
	name := safeAttachmentName(filename, index)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for n := 0; n < 1000; n++ {
		candidate := name
		if n > 0 {
			candidate = fmt.Sprintf("%s-%d%s", stem, n, ext)
		}
		path := filepath.Join(dir, candidate)
		if rel, err := filepath.Rel(dir, path); err != nil || rel != candidate {
			return "", fmt.Errorf("unsafe attachment name %q", candidate)
		}
		// O_EXCL fails on an existing file or symlink, so nothing is
		// overwritten and no link is followed.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("saving attachment: %w", err)
		}
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("saving attachment: %w", errors.Join(werr, cerr))
		}
		return path, nil
	}
	return "", errors.New("saving attachment: too many name collisions")
}

// isTextContentType reports whether the media type holds text.
func isTextContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(ct))
	}
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	switch mt {
	case "application/json", "application/xml", "application/javascript",
		"application/x-yaml", "application/yaml", "application/toml",
		"application/x-sh", "application/sql", "application/csv",
		"application/ics", "application/rtf":
		return true
	}
	return strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml")
}

// inlineText returns the attachment as text, cut to limit bytes at a rune
// boundary. truncated reports whether bytes were dropped.
func inlineText(data []byte, limit int) (text string, truncated bool) {
	if len(data) > limit {
		data = data[:limit]
		truncated = true
		for len(data) > 0 && !utf8.Valid(data) && !utf8.RuneStart(data[len(data)-1]) {
			data = data[:len(data)-1]
		}
		// Drop a final incomplete multi-byte sequence.
		if len(data) > 0 && !utf8.Valid(data) {
			if r, size := utf8.DecodeLastRune(data); r == utf8.RuneError && size <= 1 {
				data = data[:len(data)-1]
			}
		}
	}
	return strings.ToValidUTF8(string(data), "�"), truncated
}

// --- Signed download URLs (HTTP transport) ---

const defaultAttachmentURLTTL = 10 * time.Minute

var (
	attachmentURLKey     []byte // nil: download URLs are not offered
	attachmentListenAddr string
	attachmentTLS        bool
)

// setAttachmentURLKey derives the signing key from the bearer token. The key
// is a different value from the token, so a URL never reveals the token.
func setAttachmentURLKey(token string) {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("thunderbird-mcp attachment url v1"))
	attachmentURLKey = m.Sum(nil)
}

// attachmentURLTTL reads THUNDERBIRD_ATTACHMENT_URL_TTL, a Go duration.
func attachmentURLTTL() time.Duration {
	if v := os.Getenv("THUNDERBIRD_ATTACHMENT_URL_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultAttachmentURLTTL
}

func signAttachment(messageRef string, index int, exp int64) string {
	m := hmac.New(sha256.New, attachmentURLKey)
	fmt.Fprintf(m, "%s\n%d\n%d", messageRef, index, exp)
	return hex.EncodeToString(m.Sum(nil))
}

// attachmentBaseURL is THUNDERBIRD_PUBLIC_URL, else built from the request
// Host header, else from the listen address.
func attachmentBaseURL(host string) string {
	if p := strings.TrimRight(strings.TrimSpace(os.Getenv("THUNDERBIRD_PUBLIC_URL")), "/"); p != "" {
		return p
	}
	if host == "" {
		host = attachmentListenAddr
	}
	scheme := "http"
	if attachmentTLS {
		scheme = "https"
	}
	return scheme + "://" + host
}

// attachmentDownloadURL returns a short-lived signed URL, or "" when the
// server is not serving HTTP.
func attachmentDownloadURL(host, messageRef string, index int, name string) string {
	if len(attachmentURLKey) == 0 {
		return ""
	}
	exp := time.Now().Add(attachmentURLTTL()).Unix()
	q := url.Values{}
	q.Set("ref", messageRef)
	q.Set("exp", strconv.FormatInt(exp, 10))
	q.Set("sig", signAttachment(messageRef, index, exp))
	return fmt.Sprintf("%s/attachments/%d/%s?%s", attachmentBaseURL(host), index, url.PathEscape(safeAttachmentName(name, index)), q.Encode())
}

// serveAttachmentDownload streams one attachment. It is authorised only by
// the signed query token. The main bearer token is never accepted here.
func serveAttachmentDownload(w http.ResponseWriter, r *http.Request) {
	if len(attachmentURLKey) == 0 {
		http.NotFound(w, r)
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	q := r.URL.Query()
	ref, expS, sig := q.Get("ref"), q.Get("exp"), q.Get("sig")
	exp, err2 := strconv.ParseInt(expS, 10, 64)
	if err != nil || index < 0 || err2 != nil || ref == "" || sig == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	want := signAttachment(ref, index, exp)
	if !hmac.Equal([]byte(want), []byte(sig)) || time.Now().Unix() > exp {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	fn, ct, data, err := loadAttachment(ref, index)
	if err != nil {
		http.Error(w, "attachment not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": safeAttachmentName(fn, index)}))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}
