# Tools

Three domain tools, each driven by a required `action` enum. Only the parameters
relevant to the chosen action are used.

## `thunderbird_mail`

| action | parameters |
| --- | --- |
| `list_accounts` | — |
| `list_folders` | `account?` |
| `search_messages` | `account?`, `query?`, `sender?`, `recipient?`, `subject?`, `folder?`, `since?`, `until?`, `limit?`, `offset?` |
| `get_message` | `message_ref`, `body_format?` (`text`\|`html`) |
| `get_attachment` | `message_ref`, `index`, `save?` (bool) |
| `list_recent` | `account?`, `folder?`, `limit?` |
| `set_flags` | `message_ref`, `read?`, `flagged?`, `add_tags?`, `remove_tags?` |
| `move_message` | `message_ref`, `destination` |
| `delete_message` | `message_ref`, `permanent?` |
| `send_mail` | `from`, `to`, `cc?`, `bcc?`, `subject`, `body` |
| `reply_message` | `message_ref`, `from?`, `body`, `reply_all?` |
| `forward_message` | `message_ref`, `from?`, `to`, `body?` |
| `save_draft` | `from`, `to?`, `subject?`, `body?` |

To list messages, use `list_recent` (the newest indexed messages, optionally of
one account or folder) or `search_messages` with filters. There is no
`list_messages` action; a client that sends it gets a schema validation error that
lists the valid actions.

`search_messages` returns a `message_ref` for each hit; pass it to `get_message`
and the mutation actions. `set_flags`/`move_message`/`delete_message` operate on
IMAP accounts only (local folders are read-only). `send_*`/`save_draft` require
`THUNDERBIRD_ALLOW_SEND=true`.

### Attachments

`get_message` lists every attachment with its `index`, `filename`,
`content_type` and `size`. Pass the `index` to `get_attachment` with the same
`message_ref`.

`get_attachment` returns a text result with the index, filename, content type
and size, plus:

- **Saved path.** The file is written to disk and the absolute path is returned.
  This is the way to use an attachment with a client that drops embedded
  resources. Control this with `save`.
- **Inline text.** For text-like types (`text/*`, JSON, XML, YAML, TOML, CSV,
  SQL, calendar and `+json`/`+xml` types) the decoded text is returned in the
  result. It is cut at 64 KiB, on a character boundary, with a note that says
  how much was shown. PDF and other binary types are not converted to text.
- **Embedded resource.** The bytes are also returned as an MCP embedded resource
  when `save` is false, or when the file is 256 KiB or smaller. Larger saved
  files are not embedded, to keep the response small.
- **Download URL (HTTP transport only).** See below.

`save` defaults to `true` on stdio. Over HTTP the agent may run on another
machine, where a path on the server is useless, so `save` defaults to `false`
unless `THUNDERBIRD_ATTACHMENT_DIR` is set. Set `save` explicitly to override
either default. An attachment larger than `THUNDERBIRD_MAX_ATTACHMENT_BYTES`
(default 25 MiB) is refused.

Saved files go to `THUNDERBIRD_ATTACHMENT_DIR` (default: a
`thunderbird-mcp-attachments` directory in the user cache directory), in a
subdirectory per message, with mode `0600`. The filename is reduced to one safe
path element. An existing file is never overwritten: a name that is taken gets a
`-1`, `-2`, ... suffix.

#### Download URL over HTTP

Over HTTP the result also holds a URL such as
`https://host/attachments/1/report.pdf?ref=...&exp=...&sig=...`. A client on
another machine can fetch it with a plain `GET`. The URL is signed for one
message and one attachment and stops working after 10 minutes
(`THUNDERBIRD_ATTACHMENT_URL_TTL`, a Go duration such as `2m`). It needs no
`Authorization` header, and the route rejects the main bearer token.

The URL starts with `THUNDERBIRD_PUBLIC_URL` when that is set. Set it when the
server is behind a reverse proxy. Otherwise the URL uses the `Host` header of the
MCP request, and then the listen address. The scheme is `https` only when the
server has its own TLS certificate, so behind a TLS proxy `THUNDERBIRD_PUBLIC_URL`
is needed to get an `https` URL.

Security notes are in [security.md](security.md#attachments).

## `thunderbird_contacts`

| action | parameters |
| --- | --- |
| `search_contacts` | `query`, `limit?` |
| `get_contact` | `email` |

## `thunderbird_calendar`

| action | parameters |
| --- | --- |
| `list_calendars` | — |
| `list_events` | `since?`, `until?` (RFC3339 or `YYYY-MM-DD`; default: now → +30 days), `limit?` |

Dates accept RFC3339 or `YYYY-MM-DD`.

Calendar ranges use overlap and an exclusive RFC3339 `until`. Date-only `until` includes the whole UTC date.
See [calendar ranges and recurrence](calendar.md) for bounds, timezone policy, and unsupported recurrence forms.

For `search_messages` and `list_recent`, `account` is a key returned by
`list_accounts`. Omit it to query all indexed accounts; unknown keys return an
error. When both `account` and `folder` are supplied, both must match.
`limit` is an integer maximum result count (default 20 for omitted/nonpositive
values, no explicit upper cap); for example, `{"action":"list_recent","account":"account1","limit":200}`
returns up to the latest 200 indexed messages in that account.
