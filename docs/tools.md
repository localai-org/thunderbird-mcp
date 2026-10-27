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
| `list_recent` | `account?`, `folder?`, `limit?` |
| `set_flags` | `message_ref`, `read?`, `flagged?`, `add_tags?`, `remove_tags?` |
| `move_message` | `message_ref`, `destination` |
| `delete_message` | `message_ref`, `permanent?` |
| `send_mail` | `from`, `to`, `cc?`, `bcc?`, `subject`, `body` |
| `reply_message` | `message_ref`, `from?`, `body`, `reply_all?` |
| `forward_message` | `message_ref`, `from?`, `to`, `body?` |
| `save_draft` | `from`, `to?`, `subject?`, `body?` |

`search_messages` returns a `message_ref` for each hit; pass it to `get_message`
and the mutation actions. `set_flags`/`move_message`/`delete_message` operate on
IMAP accounts only (local folders are read-only). `send_*`/`save_draft` require
`THUNDERBIRD_ALLOW_SEND=true`.

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
