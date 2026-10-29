package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func parseToolFilter(env string) map[string]bool {
	if env == "" || env == "all" {
		return nil
	}
	set := map[string]bool{}
	for _, n := range strings.Split(env, ",") {
		if n = strings.TrimSpace(n); n != "" {
			set[n] = true
		}
	}
	return set
}

// mustSchema infers the JSON schema for T and overrides the "action" property's
// enum with the (dynamically gated) set of allowed values.
//
// It panics rather than calling log.Fatalf: os.Exit would skip run's deferred
// App.Close, stranding a full copy of the database in $TMPDIR. A panic unwinds
// through the defer, so the temp directory is still cleaned up.
func mustSchema[T any](enumValues []any) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(fmt.Sprintf("schema: %v", err))
	}
	if p, ok := s.Properties["action"]; ok {
		p.Enum = enumValues
	}
	return s
}

// mailActionHelp says what each mail action does. Clients choose an action
// from this text alone, and without it they invent names such as
// "list_messages" that the schema then rejects.
const mailActionHelp = "Thunderbird mail operations. Set `action` to one of the enum values. " +
	"Read actions: list_accounts (accounts and their keys); list_folders (folders, optionally of one account); " +
	"search_messages (filter by query, sender, recipient, subject, dates, account or folder); " +
	"list_recent (newest indexed messages, optionally of one account or folder; this is how to list messages, there is no list_messages); " +
	"get_message (full message by message_ref); get_attachment (one attachment by message_ref and index). " +
	"set_flags/move_message/delete_message change messages and are unavailable in read-only mode. " +
	"send_mail/reply_message/forward_message/save_draft require THUNDERBIRD_ALLOW_SEND=true."

// mailTool builds the thunderbird_mail tool. The enabled actions depend on
// the runtime mode, and the annotations follow from them.
func mailTool(readOnly, allowSend bool) *mcp.Tool {
	mailActions := []any{"list_accounts", "list_folders", "search_messages", "get_message", "list_recent", "get_attachment"}
	if !readOnly {
		mailActions = append(mailActions, "set_flags", "move_message", "delete_message")
	}
	if allowSend && !readOnly {
		mailActions = append(mailActions, "send_mail", "reply_message", "forward_message", "save_draft")
	}
	// The tool has both read-only and destructive actions, so it is annotated
	// as destructive whenever any destructive action is enabled.
	annotations := &mcp.ToolAnnotations{ReadOnlyHint: true}
	if !readOnly {
		destructive := true
		annotations = &mcp.ToolAnnotations{DestructiveHint: &destructive, ReadOnlyHint: false}
	}
	return &mcp.Tool{
		Name:        "thunderbird_mail",
		Description: mailActionHelp,
		InputSchema: mustSchema[MailInput](mailActions),
		Annotations: annotations,
	}
}

func main() {
	// All the work lives in run so that a failure returns instead of calling
	// os.Exit. log.Fatalf here skips every deferred function, and one of those
	// defers is what deletes the snapshot copies from $TMPDIR.
	if err := run(); err != nil {
		log.Fatalf("thunderbird: %v", err)
	}
}

func run() error {
	// Ctrl-C and `docker stop` are the normal way this server ends, so they
	// have to reach the cleanup path rather than killing the process outright.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Read the transport settings before loading the profile, so a bad
	// address or a missing token fails fast.
	httpCfg, err := loadHTTPConfig(os.Getenv)
	if err != nil {
		return err
	}

	profileDir, err := discoverProfile()
	if err != nil {
		return err
	}
	loaded, err := LoadApp(profileDir, os.Getenv("THUNDERBIRD_READ_ONLY") == "true", os.Getenv("THUNDERBIRD_ALLOW_SEND") == "true")
	if err != nil {
		return err
	}
	app = loaded
	// Deletes the snapshot directories. Logged, not returned: a cleanup failure
	// is worth knowing about but must not mask the server's own exit status.
	defer func() {
		if err := app.Close(); err != nil {
			log.Printf("thunderbird: cleanup: %v", err)
		}
	}()
	log.Printf("thunderbird: loaded profile %s (%d accounts)", profileDir, len(app.Config.Accounts))

	filter := parseToolFilter(os.Getenv("THUNDERBIRD_TOOLS"))
	allowed := func(name string) bool { return filter == nil || filter[name] }

	server := mcp.NewServer(&mcp.Implementation{Name: "thunderbird", Version: version}, nil)

	if allowed("thunderbird_mail") {
		mcp.AddTool(server, mailTool(app.ReadOnly, app.AllowSend), ThunderbirdMail)
	}

	if allowed("thunderbird_contacts") {
		mcp.AddTool(server, &mcp.Tool{
			Name:        "thunderbird_contacts",
			Description: "Thunderbird address book (read-only). action: search_contacts (by name/email substring) or get_contact (by exact email).",
			InputSchema: mustSchema[ContactsInput]([]any{"search_contacts", "get_contact"}),
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		}, ThunderbirdContacts)
	}

	if allowed("thunderbird_calendar") {
		mcp.AddTool(server, &mcp.Tool{
			Name:        "thunderbird_calendar",
			Description: "Thunderbird calendar (read-only). action: list_calendars or list_events (date range).",
			InputSchema: mustSchema[CalendarInput]([]any{"list_calendars", "list_events"}),
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		}, ThunderbirdCalendar)
	}

	// Run returns when the transport closes or ctx is cancelled by a signal;
	// either way the deferred cleanup below runs.
	if httpCfg != nil {
		return serveHTTP(ctx, httpCfg, server)
	}
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
