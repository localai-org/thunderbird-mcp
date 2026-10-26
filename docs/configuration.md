# Configuration

## Environment variables

| Variable | Default | Effect |
| --- | --- | --- |
| `THUNDERBIRD_PROFILE` | auto-discovered | Path to the Thunderbird profile directory. |
| `THUNDERBIRD_READ_ONLY` | `false` | When `true`, mutating and sending actions are removed. |
| `THUNDERBIRD_ALLOW_SEND` | `false` | When `true`, the compose/send actions are enabled. |
| `THUNDERBIRD_TOOLS` | all | Comma-separated allowlist of tool names (`thunderbird_mail`, `thunderbird_contacts`, `thunderbird_calendar`). |

## Profile discovery

If `THUNDERBIRD_PROFILE` is not set, the server reads `profiles.ini` from the first
platform location that exists:

- `~/.thunderbird`
- `~/.mozilla-thunderbird`
- `~/snap/thunderbird/common/.thunderbird`
- `~/.var/app/org.mozilla.Thunderbird/.thunderbird` (Flatpak)
- `~/Library/Thunderbird` (macOS)
- `%APPDATA%\Thunderbird` (Windows)

It then selects the default profile. In Docker, bind-mount the profile and set
`THUNDERBIRD_PROFILE` to the mount point.

## Running alongside Thunderbird

The server reads the profile while Thunderbird is open. Reads normally go
straight to the profile's SQLite files, which coexist fine with a running
Thunderbird; contention only shows up when Thunderbird holds an exclusive lock
or a long write transaction.

When that happens, the server transparently copies the locked database (and its
`-wal` write-ahead log, which holds everything not yet checkpointed) to a
temporary directory and reads the copy instead. A copy is reused for up to 60
seconds, and after that it is re-made only if the source actually changed, so an
actively indexing Thunderbird does not cause a copy per request.

Two consequences are worth knowing about:

- **Results can be up to 60 seconds stale.** Within that window the warm copy is
  served without consulting the live file at all, so a read can lag Thunderbird
  even after Thunderbird has released the lock.
- **The first request against a locked profile copies the whole database.** For a
  large search index that is not instant.

Copies live under the system temporary directory (`$TMPDIR`) and are removed when
the server exits, both on a normal exit and on `SIGINT`/`SIGTERM` (Ctrl-C, or
`docker stop`). A hard kill such as `SIGKILL` gives the server no chance to clean
up and leaves a copy behind.

Two things can go wrong once a database is locked:

- **The copy cannot be written**, most often because `$TMPDIR` is full. On many
  Linux systems `/tmp` is RAM-backed, so a large index really can fail to fit.
  The request then fails with an error naming the cause rather than returning
  incomplete results.
- **The copy is taken mid-write** and comes out unusable. The server retries once
  automatically, which almost always succeeds because the write window has
  closed by then. If the second copy is unusable too, the error that reaches you
  is the raw SQLite one (for example `database disk image is malformed`) rather
  than an explanation.

Earlier versions behaved differently, and in one case badly: searches over the
Thunderbird index failed loudly with `database is locked`, while **contacts and
calendar failed silently** and could return empty or incomplete results,
because they read the main database file while ignoring the write-ahead log. If
you relied on contact or calendar results collected while Thunderbird was
running, they may have been missing recent entries; it is worth re-running those
queries.

## Credentials

IMAP/SMTP passwords are decrypted from the profile's `key4.db` + `logins.json`
(the NSS store) in pure Go. If the profile is protected by a **master password**,
decryption is not possible; the server logs a warning at startup and continues
with the read-only search/contacts/calendar tools available (IMAP/SMTP actions
then fail with a clear error).

### Gmail OAuth2

The server reuses an existing Gmail refresh grant from Thunderbird’s NSS store.
It does not open a browser, request consent, or write credentials to the profile.
Other OAuth2 providers, including Outlook, remain unsupported for live IMAP/SMTP.
Their indexed mail remains searchable.

1. Sign in to your Gmail account in Thunderbird with permission to access mail.
2. Configure the IMAP and SMTP authentication methods as **OAuth2** in Thunderbird.
3. Select **SSL/TLS** or **STARTTLS** for each server. Plaintext OAuth2 connections are rejected.
4. Start this server with the same profile. No OAuth environment variables are required.
5. To enable sending, set `THUNDERBIRD_ALLOW_SEND=true`. Read-only mode still disables sending.

Supported hosts are `imap.gmail.com`, `imap.googlemail.com`, `smtp.gmail.com`,
`smtp.googlemail.com`, and `smtp-relay.gmail.com`.
A supported hostname does not override Google’s account or relay policies.
The configured authentication username must exactly match the saved grant’s username.
IMAP folder selection also matches the URI username, including percent-escaped usernames, rather than the hostname alone.

The saved login must use origin `oauth://accounts.google.com`.
Its `httpRealm` must contain `https://mail.google.com/` as a complete scope.
Calendar-only and contacts-only grants do not authorize mail.
Missing or rejected grants produce an actionable error, without a password fallback.
Sign in again through Thunderbird with mail access, then restart this server to reload credentials.

#### Client compatibility

Refresh grants belong to the OAuth client that issued them.
The implementation therefore uses Thunderbird’s built-in Google client identity and fixed token endpoint,
not a separate application registration.
Custom registrations and extension-provided OAuth clients are unsupported.
Changes to Thunderbird’s registration or Google’s policies can require an implementation update.
The embedded desktop `client_secret` is public registration data, not a confidentiality boundary.

The source reference is Mozilla’s
[OAuth2Providers.sys.mjs at commit `646deeb1ba4261849e8d0077816a1c42edcb56d3`](https://github.com/mozilla/releases-comm-central/blob/646deeb1ba4261849e8d0077816a1c42edcb56d3/mailnews/base/src/OAuth2Providers.sys.mjs).
Its Google entry defines the client identity, token endpoint, host mappings, and mail scope.
The adjacent [OAuth2Module.sys.mjs](https://github.com/mozilla/releases-comm-central/blob/646deeb1ba4261849e8d0077816a1c42edcb56d3/mailnews/base/src/OAuth2Module.sys.mjs)
and [OAuth2.sys.mjs](https://github.com/mozilla/releases-comm-central/blob/646deeb1ba4261849e8d0077816a1c42edcb56d3/mailnews/base/src/OAuth2.sys.mjs)
define saved-grant handling and refresh behavior.

#### Cache and restart limitations

IMAP and SMTP share an expiry-aware token cache in memory.
The server refreshes tokens with less than one minute remaining.
A shared lock coalesces concurrent refreshes and serializes token requests across users.
Each refresh has a 15-second HTTP timeout.
Rotated refresh tokens remain only in memory; the server never updates Thunderbird’s saved grant.
After a restart, the server loads the original grant again.
If Google invalidates that grant after rotation, sign in again through Thunderbird, then restart this server.
Concurrent Thunderbird sessions can also affect grant validity.
