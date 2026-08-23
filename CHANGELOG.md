# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-24

### Added
- Docker module (`DOC-001` … `DOC-006`): daemon socket permissions and group
  membership, daemon exposed over TCP, privileged containers, containers
  mounting `docker.sock`, containers running as root, and unrestricted
  inter-container traffic on the default bridge.
- `SECURITY.md`, `CONTRIBUTING.md`, issue templates, and a PR template.

### Notes
- A check reporting **pass** for a genuinely insecure configuration is treated
  as a security issue, not a normal bug. See `SECURITY.md`.

## [1.0.0] - 2026-08-23

### Added
- Initial release: 27 read-only checks across five modules.
  - `10-ssh` — root login, password auth, empty passwords, `MaxAuthTries`,
    X11 forwarding, host key permissions.
  - `20-filesystem` — credential file modes, world-writable files, orphaned
    files, SUID inventory, `/tmp` mount options.
  - `30-accounts` — extra UID 0 accounts, empty passwords, system accounts with
    login shells, password ageing, passwordless sudo, `authorized_keys` modes.
  - `40-network` — sockets bound to `0.0.0.0`, exposed data services, firewall
    presence, IP forwarding, kernel network flags.
  - `50-secrets` — readable `.env` files, private keys under web roots, API
    tokens in shell history, passphrase-less SSH keys.
- Three-way grading (`fail` / `warn` / `skip`) so unprivileged runs and
  non-applicable checks report honestly rather than passing vacuously.
- JSON output and `--fail-on` threshold exit codes for CI gating.
- SSH checks read effective configuration via `sshd -T`, resolving
  `sshd_config.d` drop-ins the way the daemon does.

### Fixed
- `NET-005` reported a vacuous pass on hosts without a readable `/proc/sys`;
  it now skips.

[1.1.0]: https://github.com/RootX22/sentinel-audit/releases/tag/v1.1.0
[1.0.0]: https://github.com/RootX22/sentinel-audit/releases/tag/v1.0.0
