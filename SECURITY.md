# Security

UwUSync Server keeps other people's SSH and RDP hosts, keys and passwords — sealed, so it cannot read
them, but a flaw here matters all the same. Thank you for looking.

## Reporting

Please report a vulnerability privately, through GitHub:
**[Report a vulnerability](https://github.com/MinifyX/UwUSync-Server/security/advisories/new)**.
Not in a public issue.

Say what you found, how to reproduce it, and what you think it allows. I answer within a week,
and I will tell you when a fix is out and credit you in the release notes unless you would rather
not be named.

## What is in scope

- The server: this repository, and the images at `ghcr.io/minifyx/uwusync-server`.
- `install.sh` and `update.sh`, which run as root.
- The protocol both halves speak, whose types live in the client's `uwussh-proto` crate. A flaw
  in the client itself belongs to [UwUSSH-Client](https://github.com/MinifyX/UwUSSH-Client).

What the server is designed to withstand, and what it is not — a hostile server can withhold
records, the first device trusts the setup code it was given — is written down in the
[README](README.md#what-it-can-and-cannot-see) and in
[docs/security-review-2026-09.md](docs/security-review-2026-09.md).

## Supported versions

The newest release. Updating is `sudo bash update.sh`.
