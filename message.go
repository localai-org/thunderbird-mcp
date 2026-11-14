package main

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	gomail "github.com/emersion/go-message/mail"
)

func ParseMessage(ref string, raw []byte) (MessageDetail, error) {
	d := MessageDetail{Ref: ref}
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return d, err
	}
	h := mr.Header
	d.Subject, _ = h.Subject()
	d.Date, _ = h.Date()
	d.MessageID = h.Get("Message-ID")
	d.References = h.Get("References")
	if from, _ := h.AddressList("From"); len(from) > 0 {
		d.Author = from[0].String()
	}
	for _, a := range mustAddrs(h, "To") {
		d.To = append(d.To, a.String())
	}
	for _, a := range mustAddrs(h, "Cc") {
		d.Cc = append(d.Cc, a.String())
	}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return d, err
		}
		switch ph := p.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := ph.ContentType()
			body, _ := io.ReadAll(p.Body)
			if strings.EqualFold(ct, "text/html") {
				d.BodyHTML = string(body)
			} else {
				d.BodyText += string(body)
			}
		case *gomail.AttachmentHeader:
			fn, _ := ph.Filename()
			ct, _, _ := ph.ContentType()
			body, _ := io.ReadAll(p.Body)
			d.Attachments = append(d.Attachments, Attachment{
				Index: len(d.Attachments), Filename: fn, ContentType: ct, Size: len(body),
			})
		}
	}
	return d, nil
}

func mustAddrs(h gomail.Header, key string) []*gomail.Address {
	a, _ := h.AddressList(key)
	return a
}

// ExtractAttachment returns the raw content of an attachment at the given index.
// Uses io.LimitReader to avoid loading huge files entirely into memory.
// Returns clear errors for invalid indices.
func ExtractAttachment(raw []byte, index int, limitBytes int) (filename string, contentType string, data []byte, err error) {
	if index < 0 {
		return "", "", nil, fmt.Errorf("attachment index must be >= 0, got %d", index)
	}
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return "", "", nil, fmt.Errorf("parsing message: %w", err)
	}
	attachmentCount := 0
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			// Index not found - provide count in error
			return "", "", nil, fmt.Errorf("attachment index %d not found (message has %d attachments)", index, attachmentCount)
		}
		if err != nil {
			return "", "", nil, fmt.Errorf("reading message part: %w", err)
		}
		if ah, ok := p.Header.(*gomail.AttachmentHeader); ok {
			if attachmentCount == index {
				fn, _ := ah.Filename()
				if fn == "" {
					fn = fmt.Sprintf("attachment-%d", index)
				}
				ct, _, _ := ah.ContentType()
				if ct == "" {
					ct = "application/octet-stream"
				}
				// Use LimitReader to avoid reading huge files into memory
				lr := io.LimitReader(p.Body, int64(limitBytes+1))
				body, err := io.ReadAll(lr)
				if err != nil {
					return "", "", nil, fmt.Errorf("reading attachment: %w", err)
				}
				if len(body) > limitBytes {
					return "", "", nil, fmt.Errorf("attachment exceeds size limit: %d bytes > %d bytes", len(body), limitBytes)
				}
				return fn, ct, body, nil
			}
			attachmentCount++
		}
	}
}

// SanitizeFilename removes path separators from a filename to prevent traversal attacks.
func SanitizeFilename(fn string) string {
	// Keep only the base filename, stripping any directory components.
	// Handle both Unix and Windows path separators.
	fn = filepath.Base(fn)
	// Also handle Windows backslashes on non-Windows systems
	if strings.ContainsRune(fn, '\\') {
		fn = filepath.Base(strings.ReplaceAll(fn, "\\", "/"))
	}
	return fn
}
