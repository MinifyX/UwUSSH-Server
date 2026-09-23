# Security review, September 2026

Two rounds before the first release (0.1.0), by a reviewer who had not written
the code. The first went across the whole server: authentication, accounts and
devices, the records, the pairing relay, the rate limits, TLS, backups and the
deployment. The [second](#second-round) looked at what the first one's fixes
had changed, and at `install.sh` and `update.sh`, which run as root. A
[third](#third-round-23-september-2026) went over 0.2.0. What was found, what
was fixed, and what is left on purpose.

Nothing was Critical, and nothing let one account read, write, delete or revoke
anything of another's: every query is scoped by the account loaded fresh for
the session, and a push is checked against that account's vault. What was
found were ways around the limits, ways for one account holder to wear the
server down for everybody, and one gap in what revoking a device takes away.

## Fixed

| Severity | Where | What |
| -------- | ----- | ---- |
| Medium (High behind nginx) | Rate limits | Behind a proxy, the limiter counted the **first** `X-Forwarded-For` address, which is the one the client writes itself; with nginx appending to it, every request could claim a new address. It now takes the **last** address, the one the proxy adds, across every header line, and ignores anything that is not an address. IPv6 is counted per /64, since one machine can take a fresh address from its /64 for every request. |
| Medium | Rate limits | Every check swept the whole table under one lock, so made-up addresses made every limited endpoint slower for everyone (0.7 ms per request at 50,000 addresses). Checks are now constant-time, the sweep runs once a minute, and the table holds at most 50,000 keys — beyond that a newcomer is refused rather than remembered. |
| Medium | Records | A pull page was limited by count, not size: 500 records of 256 KiB are 128 MiB, and six such pulls at once took the server from 25 MB to 1.75 GB of memory. A page now ends at 8 MiB of sealed bytes, rows are read one at a time and the reading stops there, and a push is held to the same budget. The client batches by bytes as well as by count. |
| Medium | Records | No account had a limit, so one account holder could fill the disk. An account holds at most 100,000 records and 256 MiB (`UWUSYNC_ACCOUNT_MAX_RECORDS`, `UWUSYNC_ACCOUNT_MAX_MB`, formerly `UWUSSH_…`); a push that would go past that is refused whole, and one that makes the account smaller — a delete — always goes through. The counts live on the account row, so the check does not add up every record. |
| Medium | Records, pairing | Push, pull, enrolment tokens and pairing sessions had no limit per account. Now they do (120 pushes and 600 pulls a minute, 10 tokens or pairings in ten minutes), an account can have three pairings open at once and the server a thousand, and a device four event streams. |
| Medium | Accounts | With `UWUSYNC_REGISTRATION=open` (formerly `UWUSSH_REGISTRATION`), a successful account creation was forgiven by the limiter — and there every attempt succeeds, so the five-an-hour limit never applied. Creations count now, and the server takes at most 100 accounts (`UWUSYNC_MAX_ACCOUNTS`, formerly `UWUSSH_MAX_ACCOUNTS`), checked before an invite is spent. |
| Medium | Devices | Any device could revoke every other device with its token alone. A stolen laptop could lock the owner out of their own account, one device after another, and the owner could not even add a new one. Revoking another device now takes the master password, proved the way a password change proves it; a device can still take itself out with its token. Wrong proofs are limited to ten an hour — per device, since the second round. |
| Low–Medium | Devices | Revoking a device left the enrolment tokens it had made valid for their ten minutes, its pairing sessions open, and its event stream running — so it kept hearing when the account changed. Its tokens and sessions now go with it, and an event stream checks every half minute whether its token is still good and ends when it is not. |
| Low–Medium | Devices | A wrong master password did not use up an enrolment token (on purpose: a typo should not cost the pairing). But that made a token a way to guess the password. Five wrong passwords use it up now. |
| Low | Pairing | Anybody could post as either side of a session they knew the id of, and spoil a pairing by filling the joining side's slots. Side `a` must now be the device that opened the session, signed in; side `b` holds its side with a secret it made up, and the first one to arrive keeps it. SPAKE2 already made the content worthless to a stranger; this keeps a stranger from spoiling it by speaking out of turn. |
| Low | Pairing | A long poll started listening only after it had looked for messages, so one that arrived in between woke nobody and cost the other device a whole 20 seconds. It listens first now. |
| Low | Requests | Every body up to 16 MiB was read before anything was checked, and no request had a deadline, so slow or large uploads could tie up connections. Bodies are limited to 64 KiB everywhere but the records, and every request but the event stream has two minutes. |
| Low | Sign-in | A device had one outstanding challenge, and asking for a new one replaced it — so anybody who knew a device id could keep it from ever signing in. A device may have four now, a wrong answer leaves them where they are (nobody forges an Ed25519 signature by trying again), and one that is answered is spent exactly once, even when two requests race with the same signature. |
| Low | Files | The database, its log and the backups were created readable by every user on the machine, and the certificate key was written first and made private a moment later. The server now runs with umask 077, creates the key private, and makes it private again if it finds it readable. |
| Low | Enrolment | The enrolment token travelled in the address of `GET /v1/vault/params`, which ends up in the access log of every proxy in between. It is `POST` with the token in the body now. |
| Low | Records | A device's stored read position was whatever it asked from, so a cursor from another server or from before a restore could let the purge forget tombstones that device never saw. It is capped at what the account has handed out. |

Also fixed, found alongside:

- **Pushes above 2 MiB were refused.** The framework's default body limit
  still applied on top of the server's own 16 MiB, so a batch of a few large
  records could never be sent, and a client batching by count would have been
  stuck on it for good.
- **`docker stop` took ten seconds and ended in a kill.** The server only
  listened for Ctrl-C, and as PID 1 in a container it ignored SIGTERM. It stops
  on either now, and gives open connections five seconds.
- **The old `compose.yaml` could not have started.** It bind-mounted `./data`,
  which Docker creates owned by root, for a server that runs as uid 10001. The
  stock file uses a named volume.
- **Backups went through the shared connection,** so every request waited for a
  whole `VACUUM INTO`. They read through a connection of their own now, which
  in WAL mode holds nobody up; the nightly purge lets go of the database
  between accounts.
- **A second backup on the same day failed,** because `VACUUM INTO` will not
  write over a file and backups were named by the day. They are named to the
  second.
- **A restore would have hidden new records from every device.** Devices never
  step their read position back, and a restored database starts numbering again
  from the backup's. `restore` carries every account's numbers forward past
  what the replaced database had handed out.

## Second round

No Critical, no High. Two of the first round's fixes could be turned against
the owner, and the scripts had the usual troubles of anything that runs as
root.

| Severity | Where | What |
| -------- | ----- | ---- |
| Medium | Devices | Wrong password proofs were counted per account, so a stolen device could spend the account's ten an hour — and the owner, with the right password, then got "too many requests" when revoking it. They are counted per device now: a thief only has the one. |
| Medium | Rate limits | A full table refused newcomers of every kind, accounts included, so a flood of made-up addresses could stop every push and pull that was not already counted. Accounts and devices are never refused for want of room now; an address is forgotten as soon as its own bucket's window has passed rather than after an hour, and a full table makes room from those before it refuses anybody. |
| Medium | `install.sh` | It took `compose.yaml` and the rest from the directory it was started in whenever there was a `Cargo.toml` there — and piped into bash, that is wherever root happened to be. Somebody who left a `compose.yaml` in `/tmp` could have had a privileged container started as root. Local files are only taken with `--from-checkout` now, and never from a directory anybody may write to. |
| Medium | Logs | Every refused request wrote a line, and Docker keeps a container's log for ever unless told otherwise: a few hundred requests a second fill a small disk. A refusal is logged once per address and window, a full table once a minute, and the stock `compose.yaml` keeps thirty megabytes of log. |
| Medium | Updates | The checksum next to each release file comes from the same release, so it keeps a broken download out and nothing more. That is the model UwUMail Server's updates follow, and it stays; what changed is that the documentation now says so instead of suggesting more. See [what you trust when you update](deployment.md#what-you-trust-when-you-update). |
| Low | `install.sh` | Piped into bash, `docker compose exec` read the rest of the script from standard input as its own, and the installation ended quietly before it showed the setup code. Everything it starts reads from `/dev/null` now. |
| Low | Restore | The database was moved aside before the backup was copied in, so a copy that failed left no database — and the next start would have made an empty one. The backup is made ready beside it now and swapped in last; a backup that is the database itself is refused, and a log left beside the old database is removed. |
| Low | Database | An older server started on a database a newer one had changed, and kept working on it without keeping up what the newer one added. It refuses to start now; `update.sh`'s way back puts the backup from before the update in place when that happens. |
| Low | `install.sh` | It took the **last** setup code in the log — and with open registration, a stranger could name a device after one. The code is logged as a field of its own before anybody can connect, the first one is taken, and device names are no longer logged at all. |
| Low | Devices | A device revoked from the command line kept its enrolment tokens, and its event stream only looked at the running server's own tokens. Both see the database now. |
| Low | `install.sh` | `--behind-proxy` with `--bind` on every address would have published a port whose forwarded addresses the server believes. Behind a proxy it listens on loopback only. |
| Low | Scripts | The checksum of a download was written to a predictable name in `/tmp`; it is a `mktemp` file now. |
| Low | `update.sh` | It looked in the directory the shell was in before its own, so run from another project's folder it could have worked on that project. It looks beside itself first, and only takes a directory whose `compose.yaml` runs this server. |
| Low | Scripts | `update.sh` and `compose.yaml` came from the newest stable release even for a beta or a pinned version; a relative `--dir` broke after the self-update; a failed first install could not be started again; the Compose fallback forgot `apt-get update` and Debian's package name; the way back left `compose.yaml` and `.env` as the update had made them and claimed success when it had none. All fixed. |
| Low | CI | The tag was checked against `Cargo.toml`, and the image started, only after everything was pushed — `latest` included. Both happen before now. QEMU is gone: the only stage that runs anything runs on the machine that builds, and that stage's Debian image is pinned by digest. |
| Low | TLS | A server whose key had gone would make itself a new one, and every device would refuse it. It does not while it has accounts: it stops, and says to put the key back, or to run `uwusync-server new-key` (formerly `uwussh-server new-key`) if it is lost for good. |

## Third round, 23 September 2026

A look at 0.2.0 (commit `5913c83`) by a reviewer who had not written it: the
whole repository, with the dependencies' behaviour read from their source.
Every fix of the two rounds before was checked against the code and is still
in place. No Critical, no High, and again nothing that let one account near
another's data, no way past authentication, and no panic on anything a client
can send. What was found were ways to wear the server down that the earlier
limits did not cover, and one that the earlier fixes made possible.

| ID | Severity | Where | What | Status |
| -- | -------- | ----- | ---- | ------ |
| SYNC-01 | Medium | Connections | The fifteen seconds for an idle connection held for HTTP/1.1 only. hyper has no idle deadline for HTTP/2, and any client answers its pings, so an HTTP/2 connection that said hello and then nothing held its place for good: sixteen addresses could take all 512. Each HTTP/2 connection could also carry 64 requests, and the limits of account creation, joining and pairing were counted only after the body had been read, so one address could keep a few hundred small bodies in memory for two minutes at a time. Now every connection counts what it is answering, until the last byte of the answer, and is closed once it has had nothing to answer for fifteen seconds, HTTP/2 as well; an HTTP/2 connection takes eight requests at once; and every limit that can be counted before the body is read is. That the TLS handshake has a deadline was left open by the reviewer; axum-server's acceptor gives it ten seconds. | Fixed in `4335c4d`, `ad173d0`, `ea55d8b`; wording in the README and the 0.1.1 notes corrected in `a3d6c1d` |
| SYNC-02 | Medium, Low now | Sign-in, Docker | The stock `compose.yaml` publishes the port on IPv6 too, on a network without IPv6, so Docker's proxy hands every IPv6 connection to the server from the bridge gateway: to the server, all IPv6 clients were one address. Thirty challenges a minute for made-up devices from any one of them kept every other IPv6 device from signing in. Signing in is counted per device at its address now (thirty a minute), and per address only loosely (three hundred); a device id is counted the same whether it exists or not. What IPv6 clients behind that proxy still share is one address's connections and its counts for making accounts, joining and pairing. `compose.yaml` does not ask Docker for IPv6, because on a Docker without IPv6 pools such a network does not start, and an update must not stop a running server; the deployment guide says how to publish on IPv4 only or give Docker IPv6. | Fixed in `b2b4d2e`; the rest documented in `f137da4`, Low |
| SYNC-03 | Medium | Records | A page of records is up to 11 MiB of JSON and stays in memory until the client has read it, and nothing counted how many one account had going: with 600 pulls a minute and responses never read, one account holder could fill the memory of a small machine. An account has at most four pulls and four pushes going now; a pull counts until its page has been sent or given up on, and a push is counted before its body is read. The apps pull one page after another, one request at a time. | Fixed in `70ae188`, `ea55d8b` |
| SYNC-04 | Medium | Rate limits | The second round's answer to a full table — forget whoever is done, then refuse — did not hold for account creation, whose tries are kept an hour. One attempt from each of 50,000 IPv6 networks, fourteen a second, kept every newcomer out of signing in, joining and pairing for the hour. Every bucket has a table of its own now; a full one counts a newcomer with its network (its /48, or its /24) instead of refusing it, and signing in is let through uncounted. A closed server answers account attempts before counting them. | Fixed in `68da990` |
| SYNC-05 | Low | `install.sh` | `--dir` is not checked the way `update.sh` checks its directory: pointed by the admin at a directory another local user can write to, that user could swap `compose.yaml` before it is started as root. Needs an unusual `--dir`; the default `/opt/uwusync` is fine. | Not fixed (Low) |
| SYNC-06 | Low | Quotas | The quotas count the sealed bytes of a record, not the row around it (a few hundred bytes), and an account may have any number of devices. An account at its record limit takes about 30 MB more than it is counted for. | Not fixed (Low) |
| SYNC-07 | Low | Repository | `.env` was in neither `.gitignore` nor `.dockerignore`. | Fixed in `a50cfd7` |
| SYNC-08 | Info | CI, `install.sh` | `cargo-audit` is installed at whatever version crates.io has; three CI jobs keep the read-only token in `.git/config`; Docker's install script runs without a checksum, as it always does. | Not fixed (Info) |

## Accepted, for now

- **Database work runs on the async runtime's threads, behind one lock.** Each
  query is well under a millisecond and the slow work (backups, the purge) no
  longer holds the lock, so this is not worth a thread hop per request today.
  It would be the first thing to change for a server with many busy accounts.
- **Session tokens and rate-limit counters live in memory.** A restart signs
  every device out (they sign in again with one round trip) and forgets the
  counters; an attacker who can restart the server has bigger options.
- **A hostile server can withhold records** or show a new device an older but
  consistent state. That is the limit of every zero-knowledge sync; a device
  that already knows a record notices the step backwards.
- **The first contact is trust on first use.** The setup code carries the
  fingerprint, and every later device is told it through the pairing
  handshake, so only the very first device has to get the code from somewhere
  trustworthy — the server's own log, over SSH.
- **Pairing ids are short, because they are read aloud.** Somebody flooding
  the relay from a whole IPv6 /48 could guess a live one and claim the joining
  side before the real device does. That spoils one pairing — it never reads
  one, SPAKE2 sees to that — and a new code fixes it.
- **Release files are trusted because the release is.** Signing them with a key
  CI does not hold would take a person in every release; see
  [what you trust when you update](deployment.md#what-you-trust-when-you-update).
- **After a restore, what changed since the backup lives only on the devices
  that have it.** It reaches the server again the next time it is edited there;
  a host deleted since the backup can come back on a device that joins later.
  A way for the app to push everything again is planned with the sync settings.
- **A connection that keeps asking keeps its place.** Only a connection with
  nothing to answer is closed; one that sends a request now and then stays, as
  a device's does. What bounds that is the count per address, 32 connections,
  and a server anybody can reach is best put behind a proxy that limits per
  client as well.
- **Behind Docker's proxy, IPv6 clients share one address** (SYNC-02 above).
  On a server anybody can reach over IPv6, publish on IPv4 only or give Docker
  IPv6, as [the deployment guide](deployment.md#ipv6-and-docker) says.
