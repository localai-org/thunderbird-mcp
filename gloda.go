package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Gloda struct{ db *dbSource }

// OpenGloda opens global-messages-db.sqlite read-only. Returns (nil, nil) when
// the index is absent so callers can degrade gracefully.
func OpenGloda(profileDir string) (*Gloda, error) {
	p := filepath.Join(profileDir, "global-messages-db.sqlite")
	if _, err := os.Stat(p); err != nil {
		return nil, nil
	}
	return openGlodaAt(p)
}

func openGlodaAt(path string) (*Gloda, error) {
	src, err := openDBSource(path, "gloda")
	if err != nil {
		return nil, err
	}
	return &Gloda{db: src}, nil
}

func (g *Gloda) Close() error {
	if g == nil {
		return nil
	}
	return g.db.Close()
}

type SearchQuery struct {
	Text, From, To, Subject, FolderURI string
	AccountRoot                        string // URI authority, without a trailing slash; empty means all accounts
	Since, Until                       time.Time
	Limit, Offset                      int
}

const glodaSelect = `
SELECT f.folderURI, m.messageKey, m.date, t.c1subject, t.c3author, t.c0body
FROM messagesText_content t
JOIN messages m ON m.id = t.docid
JOIN folderLocations f ON f.id = m.folderID
WHERE m.deleted = 0 AND m.folderID IS NOT NULL AND m.messageKey IS NOT NULL`

func (g *Gloda) Search(q SearchQuery) ([]MessageSummary, error) {
	if g == nil {
		return nil, fmt.Errorf("search index unavailable (gloda disabled or not built)")
	}
	sb := strings.Builder{}
	sb.WriteString(glodaSelect)
	var args []any
	like := func(col, val string) {
		if val != "" {
			sb.WriteString(" AND " + col + " LIKE ? ESCAPE '\\'")
			args = append(args, "%"+escapeLike(val)+"%")
		}
	}
	// Text matches body OR subject.
	if q.Text != "" {
		sb.WriteString(" AND (t.c0body LIKE ? ESCAPE '\\' OR t.c1subject LIKE ? ESCAPE '\\')")
		args = append(args, "%"+escapeLike(q.Text)+"%", "%"+escapeLike(q.Text)+"%")
	}
	like("t.c3author", q.From)
	like("t.c4recipients", q.To)
	like("t.c1subject", q.Subject)
	if q.AccountRoot != "" {
		// Include the slash to exclude lookalike authorities. Escape SQL LIKE
		// wildcards in usernames/hosts; also compare the literal prefix because
		// SQLite LIKE is ASCII case-insensitive even for distinct usernames.
		prefix := q.AccountRoot + "/"
		sb.WriteString(" AND f.folderURI LIKE ? ESCAPE '\\' AND substr(f.folderURI, 1, ?) = ?")
		args = append(args, escapeLike(prefix)+"%", len([]rune(prefix)), prefix)
	}
	if q.FolderURI != "" {
		sb.WriteString(" AND f.folderURI = ?")
		args = append(args, q.FolderURI)
	}
	if !q.Since.IsZero() {
		sb.WriteString(" AND m.date >= ?")
		args = append(args, q.Since.UnixMicro())
	}
	if !q.Until.IsZero() {
		sb.WriteString(" AND m.date <= ?")
		args = append(args, q.Until.UnixMicro())
	}
	sb.WriteString(" ORDER BY m.date DESC LIMIT ? OFFSET ?")
	limit := q.Limit
	if limit <= 0 {
		limit = 20
	}
	args = append(args, limit, q.Offset)
	return g.queryRows(sb.String(), args...)
}

func (g *Gloda) Recent(folderURI string, limit int) ([]MessageSummary, error) {
	return g.Search(SearchQuery{FolderURI: folderURI, Limit: limit})
}

func (g *Gloda) queryRows(query string, args ...any) ([]MessageSummary, error) {
	rows, err := g.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MessageSummary
	for rows.Next() {
		var folderURI string
		// The FTS content table allows NULL in every text column.
		var subject, author, body sql.NullString
		var key uint32
		var micros int64
		if err := rows.Scan(&folderURI, &key, &micros, &subject, &author, &body); err != nil {
			return nil, err
		}
		out = append(out, MessageSummary{
			Ref:     MessageRef{FolderURI: folderURI, MessageKey: key}.String(),
			Subject: subject.String, Author: author.String,
			Snippet: snippet(body.String, 200),
			Date:    time.UnixMicro(micros).UTC(),
		})
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	return strings.ReplaceAll(s, "_", `\_`)
}

func snippet(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
