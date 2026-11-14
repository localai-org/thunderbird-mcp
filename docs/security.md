# Security model

## Read-only guarantees

- The server **never writes** to any Thunderbird-owned file: mbox/maildir, the
  gloda index, `abook.sqlite`, the calendar database, `key4.db`, or `logins.json`.
- Every SQLite database is opened read-only (`mode=ro`, and `immutable=1` where a
  Thunderbird process might hold it).
- All message mutations go through **IMAP**, so Thunderbird picks up the change on
  its next sync rather than the server editing local state behind its back.

## Local folders are read-only

POP and "Local Folders" accounts store mail in on-disk mbox files. Writing to them
while Thunderbird is running risks corruption, so `set_flags`, `move_message`, and
`delete_message` reject local folders with a clear error. Reading them
(`search_messages`, `get_message`) is fully supported.

## Path-traversal protection

Message references are opaque `<folderURI>#<key>` strings. For local folders the
key is a byte offset and the folder URI maps to an on-disk file. The resolver
rejects any path segment that is `.`/`..`/empty or contains a separator, and
verifies the resolved path stays within the account's mail directory — so a
crafted `message_ref` cannot read arbitrary files.

## Sending is opt-in

The four compose actions are absent from the tool schema unless
`THUNDERBIRD_ALLOW_SEND=true`, and are rejected by a handler backstop even if a
client bypasses the schema. `THUNDERBIRD_READ_ONLY=true` removes all mutating and
sending actions at once.

## HTTP transport

The HTTP transport is off unless `THUNDERBIRD_HTTP_ADDR` is set, and it never runs
without a bearer token. The token is compared in constant time. The SDK's DNS
rebinding protection stays on. The server does not log the token. See
[serving over HTTP](configuration.md#serving-over-http) for the setup, including
what plain HTTP exposes.

## Credentials

Passwords are decrypted only in memory and are never logged or returned by any
tool. A master-password-protected profile cannot be decrypted; the server degrades
to read-only rather than exposing an error in place of a credential.


### Gmail OAuth2 grants

OAuth logins retain their exact origin, username, and scope realm separately from password credentials.
Password lookup never returns an OAuth refresh token.
Only known Gmail hosts can select Google grants with the complete mail scope.
The server rejects control characters in OAuth usernames before requesting a token.

Token refresh uses the fixed HTTPS endpoint `https://www.googleapis.com/oauth2/v3/token`
with normal certificate verification. The server rejects redirects.
Requests have a 15-second timeout, and responses are limited to 64 KiB.
Refresh errors do not expose response bodies, tokens, or transport error details.

Mail authentication uses SASL XOAUTH2, not LOGIN, PLAIN, or OAUTHBEARER, for Gmail OAuth2 accounts.
The server requires verified TLS or a successful STARTTLS upgrade before sending SASL credentials.
It acknowledges SASL error challenges without returning their contents to callers.
OAuth authentication errors do not expose server challenge text or SASL payloads.
Existing password authentication remains available for accounts configured to use passwords.
OAuth failures never silently fall back to passwords.

Access tokens and rotated refresh tokens stay in process memory.
Protect the process and profile as credentials: memory access can expose grants.
The public desktop client identity does not keep refresh tokens confidential.
No tool returns grants, and the server never writes them to Thunderbird’s files.
See [cache and restart limitations](configuration.md#cache-and-restart-limitations) before relying on long-running grant reuse.
OAuth support does not bypass the read-only, sending, identity, or recipient controls.

## Attachments

- `get_attachment` writes files outside the Thunderbird profile, to
  `THUNDERBIRD_ATTACHMENT_DIR`. The directories are created with mode `0700` and
  the files with `0600`. Files stay there until you delete them.
- The attachment filename comes from the sender, so it is untrusted. Only its
  last path element is used, control characters and separators are replaced,
  leading dots are removed, and the length is capped. Files are created with
  `O_EXCL`, so an existing file or symlink is never overwritten or followed. The
  per-message directory name is a hash of the message reference.
- Size is limited by `THUNDERBIRD_MAX_ATTACHMENT_BYTES`. A saved file is mail
  content from an unknown sender: do not open or run it without checking it.
- Over HTTP, `GET /attachments/<index>/<name>?ref=&exp=&sig=` serves one file.
  `sig` is an HMAC-SHA256 over the message reference, the index and the expiry,
  compared in constant time. The key is derived from the bearer token, so it
  changes when the token changes and the URL never contains the token. The route
  ignores `Authorization` and rejects any request without a valid `sig`.
  Responses use `Content-Disposition: attachment`, `nosniff` and `no-store`.
- The URL is a capability: anyone who holds it can read that one attachment until
  it expires (10 minutes by default). Web servers and proxies may log the query
  string. Use HTTPS, keep `THUNDERBIRD_ATTACHMENT_URL_TTL` short, and do not paste
  the URL in places that keep it.
