package main

import (
	"context"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A client that guesses an action name outside the advertised enum (for
// example "list_messages") is rejected by the SDK's schema validation, before
// ThunderbirdMail runs. These specs pin that behaviour over a real MCP session
// so a change to the enum or to the error text is noticed.
var _ = Describe("thunderbird_mail over MCP", func() {
	var (
		ctx context.Context
		cs  *mcp.ClientSession
	)

	BeforeEach(func() {
		f, err := os.Open("testdata/prefs.js")
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		prefs, _ := parsePrefs(f)
		a, err := loadAppFromConfig(buildConfig(prefs, "testdata"), &Credentials{}, false, false)
		Expect(err).NotTo(HaveOccurred())
		a.Gloda = buildGlodaFixture()
		old := app
		app = a
		DeferCleanup(func() { app = old })

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		DeferCleanup(cancel)

		server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
		mcp.AddTool(server, mailTool(false, false), ThunderbirdMail)
		ct, st := mcp.NewInMemoryTransports()
		ss, err := server.Connect(ctx, st, nil)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(ss.Close)
		cs, err = mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil).Connect(ctx, ct, nil)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(cs.Close)
	})

	call := func(args map[string]any) *mcp.CallToolResult {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "thunderbird_mail", Arguments: args})
		Expect(err).NotTo(HaveOccurred())
		return res
	}

	It("rejects the unknown action list_messages at schema validation", func() {
		res := call(map[string]any{"action": "list_messages", "account": "account5"})
		Expect(res.IsError).To(BeTrue())
		msg := res.Content[0].(*mcp.TextContent).Text
		Expect(msg).To(ContainSubstring("validating /properties/action"))
		Expect(msg).To(ContainSubstring("list_messages does not equal any of"))
		// The error names the real actions, which is how a client recovers.
		Expect(msg).To(ContainSubstring("list_recent"))
		// The handler's own "unknown mail action" branch is never reached.
		Expect(msg).NotTo(ContainSubstring("unknown mail action"))
	})

	It("accepts list_recent for the same arguments", func() {
		res := call(map[string]any{"action": "list_recent", "account": "account5"})
		Expect(res.Content[0].(*mcp.TextContent).Text).NotTo(ContainSubstring("validating"))
	})

	It("tells clients that list_recent lists messages", func() {
		Expect(mailTool(false, false).Description).To(ContainSubstring("list_recent"))
		Expect(mailTool(false, false).Description).To(ContainSubstring("there is no list_messages"))
	})
})
