# UwUSSH Server

The sync server behind [UwUSSH](https://github.com/MinifyX/UwUSSH-Client): your
hosts, keys and passwords on all your devices, on a machine that belongs to you.

It is a **dumb, encrypted mailbox**. It hands out sequence numbers, keeps the
newest version of every record, pages through them from a cursor, and refuses a
write whose version is not the one it holds. It cannot read a single field of
what it stores — not a hostname, not an address, not a password — because
everything is sealed with a key it never sees.

One Rust binary. One SQLite file. No account with us, no telemetry, no
subscription.

## Run it

```yaml
services:
  uwussh:
    image: ghcr.io/minifyx/uwussh-server:latest
    restart: unless-stopped
    ports: ['8443:8443']
    volumes: ['./data:/data']
    environment:
      UWUSSH_PUBLIC: nas.lan:8443
      UWUSSH_REGISTRATION: invite
```

```bash
docker compose up -d && docker compose logs uwussh
```

The first start writes a **setup code** to the log — one string carrying the
address and an invite. Paste it into UwUSSH under Settings → Sync, type your
master password once, and that device is in. Later ones get another code:

```bash
docker compose exec uwussh uwussh-server invite
```

Without Docker: `cargo build --release`, then run `uwussh-server`. It needs a
folder (`UWUSSH_DATA`, `./data` by default) and nothing else.

## Adding a second device

Not by typing an address and a password on the new device. The device that is
already in shows a short code; the new one types it; the two agree on a key the
server cannot derive, and through that channel the first device passes what the
second needs — including a one-time enrolment token. The new device then proves
it knows the master password, and only then does the server hand over the
wrapped vault key.

Two secrets, and neither is enough on its own: an intercepted code is worth
nothing without the password, and the password is worth nothing without a
device that approved the join.

## What it can and cannot see

| It sees                                    | It does not see                                     |
| ------------------------------------------ | --------------------------------------------------- |
| How many records there are, and of what kind | Host names, addresses, users                         |
| When they changed, and from which device    | Passwords, private keys, passphrases, snippet bodies |
| How many devices an account has             | Which servers you have, or that you have any         |

The header of every record — which record, what kind, whose vault, when, and
whether it is deleted — is sealed **along with** the payload. So this server
cannot mark a record deleted (which would remove it from every device, since a
delete beats a concurrent edit), cannot hand an old version back as the newest
one, and cannot move a blob to another record. A device drops such an envelope
instead of applying it.

What a hostile server could still do is stay silent: withhold records, or show
a brand-new device an older but consistent state. That is the limit of every
zero-knowledge sync, and a device that already knows a record notices the step
backwards.

Since it also stores the wrapped vault key, the client mixes an **account key**
into the key derivation — 128 random bits that live only on paired devices and
in the recovery kit. Whoever takes a copy of this database cannot even start
guessing the master password against it.

## Configuration

| Variable                 | Default        | What it does                                                      |
| ------------------------ | -------------- | ----------------------------------------------------------------- |
| `UWUSSH_DATA`            | `./data`       | Database, and backups under `backups/`                            |
| `UWUSSH_LISTEN`          | `0.0.0.0:8443` | Address to listen on                                              |
| `UWUSSH_PUBLIC`          | the listen address | How devices reach this server; goes into the setup code       |
| `UWUSSH_REGISTRATION`    | `invite`       | `open`, `invite` or `closed`                                      |
| `UWUSSH_TRUST_FORWARDED` | off            | Believe `X-Forwarded-For` — only behind a proxy that sets it      |
| `UWUSSH_SESSION_SECS`    | `3600`         | How long a device's token lasts before it signs a challenge again |

## The commands

```
uwussh-server              serve (the default)
uwussh-server invite       a code for one new account, good for a week
uwussh-server accounts     what is on this server, and how many devices each has
uwussh-server devices <id> the devices of an account
uwussh-server revoke <id>  shut a device out
uwussh-server backup       a consistent copy, right now
```

Backups run by themselves too: one a night, fourteen kept, written with
`VACUUM INTO` — copying a live SQLite file would give you the database without
its write-ahead log, which is a backup that looks fine until you need it.

## The protocol

Nine endpoints. The types come from
[`uwussh-proto`](https://github.com/MinifyX/UwUSSH-Client/tree/main/crates/uwussh-proto),
the same crate the client uses, so a schema change is one edit in one place.

| Endpoint                                     | What it is for                                        |
| -------------------------------------------- | ----------------------------------------------------- |
| `POST /v1/accounts`                          | Create an account from an invite                      |
| `POST /v1/session/challenge`, `POST /v1/session` | A device signs a challenge and gets a token        |
| `GET /v1/vault`, `GET /v1/vault/params`      | The vault header; the parameters a joining device needs |
| `PUT /v1/vault/key`                          | A new master password: rewrap, no record touched      |
| `GET /v1/records`, `POST /v1/records`        | Pull from a cursor, push with a version               |
| `GET /v1/events`                             | "There is something new from N" (server-sent events)  |
| `GET /v1/devices`, `POST /v1/devices/invite`, `POST /v1/devices/enrol`, `DELETE /v1/devices/{id}` | Devices: list, let one in, shut one out |
| `GET /healthz`                               | Alive, and what schema it speaks                      |

Limits it enforces without a key: 500 records per request, 256 KiB per record,
16 MiB per request, and rate limits on the three endpoints where guessing would
pay.

## TLS

**Not yet.** Put it behind a reverse proxy with a real certificate for now
(Caddy, Traefik, nginx) and set `UWUSSH_TRUST_FORWARDED=1`. The client refuses
plain HTTP to anything but localhost.

The next step is `UWUSSH_TLS=auto`: a certificate the server makes for itself on
first start, whose fingerprint goes into the setup code and is pinned by the
client — the same thing an SSH client does with a host key, and no domain
needed.

## Building on it

```bash
cargo test            # unit tests, and the API over real HTTP
cargo clippy --all-targets -- -D warnings
```

`tests/api.rs` drives the real server the way a device does: create an account,
sign a challenge, push, pull, join a second device, revoke it. The client's own
`MemoryServer` follows the same rules without a network, so both sides are
tested against one definition of what this server does.

## Licence

GPL-3.0-only, like the rest of UwUSSH. If you hand on a changed version, hand
on the source too.
