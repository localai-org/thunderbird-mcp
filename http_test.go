package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const testHTTPToken = "0123456789abcdef-token"

var _ = Describe("loadHTTPConfig", func() {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	It("stays on stdio when no address is set", func() {
		cfg, err := loadHTTPConfig(env(map[string]string{"THUNDERBIRD_HTTP_TOKEN": testHTTPToken}))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	It("reads the token from the environment", func() {
		cfg, err := loadHTTPConfig(env(map[string]string{"THUNDERBIRD_HTTP_ADDR": "127.0.0.1:8080", "THUNDERBIRD_HTTP_TOKEN": testHTTPToken}))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.Addr).To(Equal("127.0.0.1:8080"))
		Expect(cfg.Token).To(Equal(testHTTPToken))
	})

	It("reads the token from a file and trims the newline", func() {
		path := filepath.Join(GinkgoT().TempDir(), "token")
		Expect(os.WriteFile(path, []byte(testHTTPToken+"\n"), 0o600)).To(Succeed())
		cfg, err := loadHTTPConfig(env(map[string]string{"THUNDERBIRD_HTTP_ADDR": "127.0.0.1:8080", "THUNDERBIRD_HTTP_TOKEN_FILE": path}))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.Token).To(Equal(testHTTPToken))
	})

	DescribeTable("rejects a bad setup",
		func(m map[string]string, want string) {
			_, err := loadHTTPConfig(env(m))
			Expect(err).To(MatchError(ContainSubstring(want)))
		},
		Entry("no token, even on loopback",
			map[string]string{"THUNDERBIRD_HTTP_ADDR": "127.0.0.1:8080"}, "requires THUNDERBIRD_HTTP_TOKEN"),
		Entry("short token",
			map[string]string{"THUNDERBIRD_HTTP_ADDR": "127.0.0.1:8080", "THUNDERBIRD_HTTP_TOKEN": "short"}, "at least 16"),
		Entry("both token sources",
			map[string]string{"THUNDERBIRD_HTTP_ADDR": "127.0.0.1:8080", "THUNDERBIRD_HTTP_TOKEN": testHTTPToken, "THUNDERBIRD_HTTP_TOKEN_FILE": "/x"}, "only one of"),
		Entry("address without a port",
			map[string]string{"THUNDERBIRD_HTTP_ADDR": "localhost", "THUNDERBIRD_HTTP_TOKEN": testHTTPToken}, "THUNDERBIRD_HTTP_ADDR"),
		Entry("certificate without a key",
			map[string]string{"THUNDERBIRD_HTTP_ADDR": "127.0.0.1:8080", "THUNDERBIRD_HTTP_TOKEN": testHTTPToken, "THUNDERBIRD_HTTP_TLS_CERT": "c.pem"}, "set together"),
		Entry("missing token file",
			map[string]string{"THUNDERBIRD_HTTP_ADDR": "127.0.0.1:8080", "THUNDERBIRD_HTTP_TOKEN_FILE": "/nonexistent/token"}, "THUNDERBIRD_HTTP_TOKEN_FILE"),
	)
})

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

var _ = Describe("MCP over HTTP", func() {
	var (
		ctx context.Context
		ts  *httptest.Server
	)

	BeforeEach(func() {
		f, err := os.Open("testdata/prefs.js")
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		prefs, _ := parsePrefs(f)
		a, err := loadAppFromConfig(buildConfig(prefs, "testdata"), &Credentials{}, false, false)
		Expect(err).NotTo(HaveOccurred())
		old := app
		app = a
		DeferCleanup(func() { app = old })

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)

		server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
		mcp.AddTool(server, &mcp.Tool{
			Name:        "thunderbird_mail",
			InputSchema: mustSchema[MailInput]([]any{"list_accounts"}),
		}, ThunderbirdMail)
		ts = httptest.NewServer(newHTTPHandler(server, testHTTPToken))
		DeferCleanup(ts.Close)
	})

	connect := func(token string) (*mcp.ClientSession, error) {
		transport := &mcp.StreamableClientTransport{
			Endpoint:   ts.URL + "/mcp",
			HTTPClient: &http.Client{Transport: bearerTransport{token}},
			MaxRetries: -1,
		}
		return mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, transport, nil)
	}

	statusOf := func(header string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{}`))
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		// A short timeout turns a handler that wrongly lets the request
		// through (and then waits for more input) into a clear failure.
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		return resp.StatusCode
	}

	It("rejects a request without a token", func() {
		Expect(statusOf("")).To(Equal(http.StatusUnauthorized))
	})

	It("rejects a wrong token, a prefix of the token and another scheme", func() {
		Expect(statusOf("Bearer wrong-token-value-xx")).To(Equal(http.StatusUnauthorized))
		Expect(statusOf("Bearer " + testHTTPToken[:10])).To(Equal(http.StatusUnauthorized))
		Expect(statusOf("Basic " + testHTTPToken)).To(Equal(http.StatusUnauthorized))
	})

	It("does not serve the MCP endpoint on other paths", func() {
		resp, err := (&http.Client{Transport: bearerTransport{testHTTPToken}}).Get(ts.URL + "/")
		Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
	})

	It("lets a client with the token initialize and call a tool", func() {
		cs, err := connect(testHTTPToken)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(cs.Close)
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "thunderbird_mail", Arguments: map[string]any{"action": "list_accounts"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.IsError).To(BeFalse())
	})

	It("refuses to connect a client with the wrong token", func() {
		_, err := connect("wrong-token-value-xx")
		Expect(err).To(HaveOccurred())
	})

	It("serves several sessions at once without a data race", func() {
		const sessions, calls = 6, 15
		var wg sync.WaitGroup
		errs := make(chan error, sessions*calls)
		for i := 0; i < sessions; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cs, err := connect(testHTTPToken)
				if err != nil {
					errs <- err
					return
				}
				defer cs.Close()
				for j := 0; j < calls; j++ {
					res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "thunderbird_mail", Arguments: map[string]any{"action": "list_accounts"}})
					if err == nil && res.IsError {
						err = context.DeadlineExceeded
					}
					if err != nil {
						errs <- err
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		Expect(errs).To(BeEmpty())
	})
})

var _ = Describe("serveHTTPOn", func() {
	It("stops when the context ends", func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- serveHTTPOn(ctx, ln, &httpConfig{Token: testHTTPToken}, mcp.NewServer(&mcp.Implementation{Name: "t", Version: "t"}, nil))
		}()
		cancel()
		Eventually(done, 5*time.Second).Should(Receive(BeNil()))
	})
})
