package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// minHTTPTokenLen rejects guessable tokens. 16 characters of a random token
// is far past what an online guess can reach.
const minHTTPTokenLen = 16

// httpConfig is the HTTP transport setup. A nil *httpConfig means stdio.
type httpConfig struct {
	Addr     string
	Token    string
	CertFile string
	KeyFile  string
}

// loadHTTPConfig reads the HTTP transport settings. It returns (nil, nil) when
// THUNDERBIRD_HTTP_ADDR is unset, which keeps the server on stdio.
//
// The server can read and, when enabled, send mail, so there is no
// unauthenticated mode: a token is required for every address, loopback
// included. Any web page the user opens can reach a loopback port.
func loadHTTPConfig(getenv func(string) string) (*httpConfig, error) {
	addr := getenv("THUNDERBIRD_HTTP_ADDR")
	if addr == "" {
		return nil, nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("THUNDERBIRD_HTTP_ADDR %q: %w", addr, err)
	}
	cfg := &httpConfig{Addr: addr, CertFile: getenv("THUNDERBIRD_HTTP_TLS_CERT"), KeyFile: getenv("THUNDERBIRD_HTTP_TLS_KEY")}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("THUNDERBIRD_HTTP_TLS_CERT and THUNDERBIRD_HTTP_TLS_KEY must be set together")
	}

	token, file := getenv("THUNDERBIRD_HTTP_TOKEN"), getenv("THUNDERBIRD_HTTP_TOKEN_FILE")
	switch {
	case token != "" && file != "":
		return nil, errors.New("set only one of THUNDERBIRD_HTTP_TOKEN and THUNDERBIRD_HTTP_TOKEN_FILE")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("reading THUNDERBIRD_HTTP_TOKEN_FILE: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		return nil, errors.New("THUNDERBIRD_HTTP_ADDR requires THUNDERBIRD_HTTP_TOKEN or THUNDERBIRD_HTTP_TOKEN_FILE")
	}
	if len(token) < minHTTPTokenLen {
		return nil, fmt.Errorf("the HTTP token must be at least %d characters", minHTTPTokenLen)
	}
	cfg.Token = token
	return cfg, nil
}

// bearerVerifier accepts exactly one static token. Both sides are hashed first
// so the comparison takes the same time whatever the length of the guess.
func bearerVerifier(token string) auth.TokenVerifier {
	want := sha256.Sum256([]byte(token))
	return func(_ context.Context, got string, _ *http.Request) (*auth.TokenInfo, error) {
		sum := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
			return nil, auth.ErrInvalidToken
		}
		// RequireBearerToken rejects a token without an expiry.
		return &auth.TokenInfo{Expiration: time.Now().Add(24 * time.Hour)}, nil
	}
}

// newHTTPHandler serves the MCP Streamable HTTP transport at /mcp behind the
// bearer token. Every session shares the one server. The SDK's DNS rebinding
// protection stays on.
func newHTTPHandler(server *mcp.Server, token string) http.Handler {
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", auth.RequireBearerToken(bearerVerifier(token), nil)(mcpHandler))
	return mux
}

// serveHTTP listens on cfg.Addr until ctx ends, then drains open requests.
func serveHTTP(ctx context.Context, cfg *httpConfig, server *mcp.Server) error {
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	return serveHTTPOn(ctx, ln, cfg, server)
}

func serveHTTPOn(ctx context.Context, ln net.Listener, cfg *httpConfig, server *mcp.Server) error {
	srv := &http.Server{
		Handler:           newHTTPHandler(server, cfg.Token),
		ReadHeaderTimeout: 10 * time.Second,
	}
	tls := cfg.CertFile != ""
	if !tls {
		log.Printf("thunderbird: serving HTTP on %s without TLS; the token travels in clear text unless a TLS proxy fronts it", ln.Addr())
	}
	log.Printf("thunderbird: MCP over HTTP at %s/mcp", ln.Addr())

	errc := make(chan error, 1)
	go func() {
		if tls {
			errc <- srv.ServeTLS(ln, cfg.CertFile, cfg.KeyFile)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
