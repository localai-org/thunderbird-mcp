# thunderbird-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes a local **Thunderbird** profile — mail, contacts, and calendar — to an LLM.

It reads Thunderbird's own on-disk state directly (`prefs.js`, the gloda search index, the NSS credential store, the address book and calendar databases) and uses IMAP/SMTP for anything live. No Thunderbird extension is required, and it works whether or not Thunderbird is running.

- **[Configuration](configuration.md)** — environment variables, profile discovery and [serving over HTTP](configuration.md#serving-over-http)
- **[Tools](tools.md)** — the three tools and every action's parameters
- **[Security](security.md)** — the read-only guarantees and the send/write gating

## Install

```bash
curl -fsSL https://mudler.github.io/thunderbird-mcp/install.sh | sh
```

The script installs the latest release binary (Linux/macOS, amd64/arm64) to `~/.local/bin` after verifying its checksum. Set `BINDIR` to change the destination and `VERSION` to pin a release.

Alternatives:

```bash
docker pull ghcr.io/mudler/thunderbird-mcp:latest
# or
go install github.com/mudler/thunderbird-mcp@latest
```
