# Changelog

Each release gets a section here before its tag is pushed; CI copies the section into the GitHub
release. Versions follow semver; `-beta.N` versions are pre-releases.

## 0.1.0

**The first release.** A sync server for [UwUSSH](https://github.com/MinifyX/UwUSSH-Client): your
hosts, keys and passwords on all your devices, through a machine that belongs to you and cannot
read a single field of what it keeps.

**Setting it up is one command.** `install.sh` installs Docker when it is missing, asks how your
devices reach the machine, starts the server and shows a setup code to paste into UwUSSH. No
domain, no certificate to get: the server makes its own and your devices pin its key, the way an
SSH client pins a host key. It runs just as well behind Caddy or nginx.

**Updating is one command too.** `update.sh` takes a newer copy of itself, backs up, pulls the new
image and waits for the server's health check — and if the new version does not come up, the one
from before goes back in. Once a day the server looks whether there is something newer and says so
in its log. Images for amd64 and arm64, as `latest`, `beta` and `edge`.

What is in it:

- **Zero knowledge.** Every record is sealed on the device, header and all, so the server cannot
  read it, move it to another record, mark it deleted or hand an old version back as new. It hands
  out sequence numbers, keeps the newest version of each record, and refuses a write based on a
  version it no longer holds.
- **An account key** next to the master password, so a copy of the server's database is not even
  a place to start guessing the password.
- **Devices sign in** with a key of their own, by signing a challenge. A new device joins from one
  that is already in, with three spoken words: the two run SPAKE2 through the server, which carries
  the messages and understands none of them.
- **Limits** where guessing or hammering would pay, and on what one account may hold.
- **Backups** every night and before every update, and `uwussh-server restore` to put one back.
- **A distroless image** that runs as an unprivileged user on a read-only file system, with no
  capability at all.

Reviewed before release by someone who had not written it: nothing critical, and nothing that let
one account near another's data; every finding is fixed, each with a test. The details are in
[docs/security-review-2026-09.md](docs/security-review-2026-09.md).

The app's side — Settings → Sync — comes with the next UwUSSH beta.
