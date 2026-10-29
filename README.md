# 🐦 thunderbird-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes a local **Thunderbird** profile — mail, contacts, and calendar — to an LLM.

[![CI](https://github.com/mudler/thunderbird-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/mudler/thunderbird-mcp/actions/workflows/ci.yml)
[![Release](https://github.com/mudler/thunderbird-mcp/actions/workflows/release.yml/badge.svg)](https://github.com/mudler/thunderbird-mcp/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-mudler%2Fthunderbird--mcp-blue?logo=docker)](https://github.com/mudler/thunderbird-mcp/pkgs/container/thunderbird-mcp)

It works with any MCP client and is designed to pair with [LocalAI](https://localai.io/docs/features/mcp).

---

## What it does

`thunderbird-mcp` reads Thunderbird's **own on-disk state** directly and uses **IMAP/SMTP** for anything live. There is no Thunderbird extension or add-on to install, and it works whether or not Thunderbird is running.

| Data source | File in the profile | Access |
| --- | --- | --- |
| Accounts, SMTP, calendars | `prefs.js` | read |
| Full-text search index | `global-messages-db.sqlite` (gloda) | read-only |
| Credentials | `key4.db` + `logins.json` (NSS) | read-only, decrypted in pure Go |
| Contacts | `abook.sqlite` | read-only |
| Calendar | `calendar-data/local.sqlite`, `calendar-data/cache.sqlite` | read-only |
| Live mail | IMAP / SMTP | fetch, mutate, send |

It is a single, static, **CGO-free** Go binary.

**Expected latency while Thunderbird holds a lock.** SQLite databases are normally read live, even with Thunderbird running. When Thunderbird does hold an exclusive lock, the first affected request waits about 5 seconds for it, then falls back to copying the database to a private snapshot, so a large search index is not instant. Subsequent requests are served from that snapshot and are fast for the next 60 seconds. Startup can pay the same wait once per data source. This is expected behaviour, not a hang.

## Tools

Three domain tools, each driven by an `action` enum:

### `thunderbird_mail`
`list_accounts`, `list_folders`, `search_messages`, `get_message`, `list_recent`, `get_attachment`, `set_flags`, `move_message`, `delete_message`, `send_mail`, `reply_message`, `forward_message`, `save_draft`

### `thunderbird_contacts`
`search_contacts`, `get_contact`

### `thunderbird_calendar`
`list_calendars`, `list_events`

The `action` enum is built **dynamically**: write actions (`set_flags`/`move_message`/`delete_message`) appear only when writes are allowed, and send actions (`send_mail`/`reply_message`/`forward_message`/`save_draft`) only when `THUNDERBIRD_ALLOW_SEND=true`. A disabled action is not even present in the schema.

See [calendar range and recurrence semantics](docs/calendar.md) for calendar limits and timezone policy.

See [docs/tools.md](docs/tools.md) for the full per-action parameter reference.

## Safety model

- **Never writes to any Thunderbird-owned file** (mbox/maildir/gloda/abook/calendar/`key4.db`/`logins.json`). Every SQLite database is opened read-only. All mutations go through IMAP, where the server syncs.
- **Local (POP/Local Folders) accounts, contacts, and calendar are read-only.**
- **Sending is gated** behind `THUNDERBIRD_ALLOW_SEND=true` (off by default). `THUNDERBIRD_READ_ONLY=true` disables every mutating and sending action.
- Local message paths are resolved with **path-traversal protection** — a crafted `message_ref` cannot escape the profile directory.

More detail in [docs/security.md](docs/security.md).

## Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `THUNDERBIRD_PROFILE` | auto-discovered | path to the profile directory |
| `THUNDERBIRD_READ_ONLY` | `false` | when `true`, mutating and sending actions are unavailable |
| `THUNDERBIRD_ALLOW_SEND` | `false` | when `true`, the compose/send actions are enabled |
| `THUNDERBIRD_TOOLS` | all | comma-separated allowlist of the three tool names |
| `THUNDERBIRD_HTTP_ADDR` | unset (stdio) | `host:port` to serve MCP over HTTP instead of stdio. Requires a token; see [docs/configuration.md](docs/configuration.md#serving-over-http). |
| `THUNDERBIRD_HTTP_TOKEN` | unset | Bearer token for HTTP clients, at least 16 characters. |
| `THUNDERBIRD_HTTP_TOKEN_FILE` | unset | File holding the token. Use it instead of `THUNDERBIRD_HTTP_TOKEN`, not with it. |
| `THUNDERBIRD_HTTP_TLS_CERT`, `THUNDERBIRD_HTTP_TLS_KEY` | unset | PEM files to serve HTTPS. Set both or neither. |

## Quick start

### One-liner (Linux/macOS)

```bash
curl -fsSL https://mudler.github.io/thunderbird-mcp/install.sh | sh
```

Installs the latest release binary (amd64/arm64) to `~/.local/bin` after verifying its checksum against the release's `checksums.txt`. `BINDIR=/usr/local/bin` changes the destination, `VERSION=v0.1.0` pins a release.

### Docker

```bash
docker run -i --rm --network host \
  -e THUNDERBIRD_PROFILE=/profile \
  -v "$HOME/.thunderbird/xxxx.default-release:/profile:ro" \
  ghcr.io/mudler/thunderbird-mcp:latest
```

`--network host` lets the container reach your IMAP/SMTP servers; mounting the profile read-only is recommended (the server never writes to it).

### From source

```bash
go install github.com/mudler/thunderbird-mcp@latest
THUNDERBIRD_PROFILE=~/.thunderbird/xxxx.default-release thunderbird-mcp
```

### LocalAI

Add to your model configuration:

```yaml
mcp:
  stdio: |
    {
      "mcpServers": {
        "thunderbird": {
          "command": "docker",
          "args": [
            "run", "-i", "--rm", "--network", "host",
            "-e", "THUNDERBIRD_PROFILE=/profile",
            "-e", "THUNDERBIRD_ALLOW_SEND=false",
            "-v", "/home/user/.thunderbird/xxxx.default-release:/profile:ro",
            "ghcr.io/mudler/thunderbird-mcp:latest"
          ]
        }
      }
    }
```

## Gmail OAuth2

Live IMAP and SMTP can reuse Gmail OAuth2 grants saved by Thunderbird.
Sign in through Thunderbird first with mail access, then start this server.
Both protocols require TLS or STARTTLS. No separate consent flow is available.
Sending still requires `THUNDERBIRD_ALLOW_SEND=true`.

See [Gmail setup and compatibility](docs/configuration.md#gmail-oauth2) for supported hosts,
credential requirements, and recovery steps.

## Limitations (non-goals)

- **OAuth2 providers other than Gmail**, including Outlook, are unsupported for live IMAP/SMTP. Their indexed mail remains searchable.
- Gmail support requires Thunderbird’s built-in Google client registration. Custom OAuth clients and a new consent flow are unsupported.
- A profile protected by a **master password** cannot have its credentials decrypted — the server logs a warning and keeps the read-only search/contacts/calendar tools working.
- No calendar or contact **writes**.

## Development

```bash
go test ./...          # ginkgo suite
go vet ./...
CGO_ENABLED=0 go build .
```

The credential-decryption path is covered by a regression test against a **real** NSS `key4.db`/`logins.json` fixture (generated by the NSS library itself), in addition to synthetic round-trip tests.

## License

[MIT](./LICENSE)
