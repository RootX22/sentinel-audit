# sentinel-audit

A dependency-free Linux server hardening auditor in pure Bash. Point it at a
freshly-provisioned box and it tells you what an attacker would find first.

```
sentinel-audit 1.0.0  2026-08-23T16:19:06Z
host: web-01   os: Ubuntu 24.04.1 LTS   privilege: root

▸ SSH
  ✓ Root login over SSH is disabled                    [SSH-001]
  ✗ Password authentication is enabled                 [SSH-002]
      Set 'PasswordAuthentication no' and deploy keys — passwords are
      credential-stuffable, keys are not
  ✓ Empty passwords are rejected                       [SSH-003]

▸ Network
  ✗ Data service(s) exposed on all interfaces: Redis:6379   [NET-002]
      Bind to 127.0.0.1 or restrict with firewall rules

─────────────────────────────────────────────
28 passed   2 failed   4 warnings   0 skipped
score: 82% of applicable checks passed
```

## Why another hardening script

Most of them either need a package manager, a Python runtime, and a config
file before they run at all — or they're a wall of `grep sshd_config` that
misses everything set in `sshd_config.d/`.

This one is deliberately narrow:

* **Zero dependencies.** Bash 4 and coreutils. No jq, no Python, no packages to
  install. It runs on a minimal container or a box you just SSH'd into for the
  first time.
* **Strictly read-only.** No check writes a file, restarts a service, or edits a
  config. An auditor you can't trust to be inert is one you won't run on
  production — so inertness is enforced by design, not by discipline.
* **Reads effective config, not files.** SSH checks go through `sshd -T`, which
  resolves `Include` directives and `Match` blocks the way the daemon actually
  does. Grepping `/etc/ssh/sshd_config` misses the drop-in files where most
  modern distros keep their real settings.
* **Honest about what it couldn't check.** Running without root produces skips,
  not silent passes. A host with no `/proc/sys` reports "not readable" rather
  than a vacuous green tick.

## Install

```bash
git clone https://github.com/RootX22/sentinel-audit.git
cd sentinel-audit
chmod +x sentinel.sh
sudo ./sentinel.sh
```

There is no install step, and there doesn't need to be one.

## Usage

```bash
./sentinel.sh                        # human-readable report
sudo ./sentinel.sh                   # includes root-only checks
./sentinel.sh --format json          # machine-readable, for CI
./sentinel.sh --only ssh,network     # run a subset
./sentinel.sh --fail-on warn         # exit non-zero on warnings too
```

**Exit codes** — `0` clean, `1` findings at or above the `--fail-on` threshold,
`2` usage error. Suitable for a CI gate as-is.

## What it checks

| Module | ID range | Covers |
|---|---|---|
| `10-ssh` | `SSH-00x` | Root login, password auth, empty passwords, `MaxAuthTries`, X11 forwarding, host key permissions |
| `20-filesystem` | `FS-00x` | `/etc/passwd`,`/etc/shadow`,`/etc/group` modes, world-writable files, orphaned files, SUID inventory, `/tmp` mount options |
| `30-accounts` | `ACC-00x` | Extra UID 0 accounts, empty passwords, system accounts with login shells, password ageing, passwordless sudo, `authorized_keys` permissions |
| `40-network` | `NET-00x` | Sockets bound to `0.0.0.0`, exposed data services, firewall presence, IP forwarding, kernel network flags |
| `50-secrets` | `SEC-00x` | World-readable `.env` files, private keys under web roots, API tokens in shell history, passphrase-less SSH keys |

Findings are graded three ways, and the distinction matters:

* **fail** — exploitable or directly exposes credentials.
* **warn** — weakens defence in depth, or is legitimate in some deployments
  (`PermitRootLogin prohibit-password`, IP forwarding on a Docker host).
* **skip** — genuinely not applicable. A box with no SSH daemon is not
  penalised for its sshd config.

## In CI

```yaml
- name: Hardening audit
  run: ./sentinel.sh --format json > audit.json || true

- name: Gate on findings
  run: |
    fails=$(jq '.summary.fail' audit.json)
    [ "$fails" -eq 0 ] || { jq '.findings[] | select(.status=="fail")' audit.json; exit 1; }
```

## Writing a check

Drop a file into `checks/`. The numeric prefix sets run order — externally
exposed surface first. `lib/core.sh` is already sourced, so `pass`, `fail`,
`warn`, `skip`, `section`, `have`, `is_root`, `sshd_option` and `file_mode` are
all available:

```bash
section "My Service"

if ! have myservice; then
    skip MYS-001 "myservice configuration" "not installed"
    return 0 2>/dev/null || exit 0
fi

if myservice --check-tls >/dev/null 2>&1; then
    pass MYS-001 "TLS is enforced"
else
    fail MYS-001 "TLS is not enforced" "Set tls=required in /etc/myservice.conf"
fi
```

A module that errors out costs you that module, not the run — the runner catches
it and continues.

## Scope

This audits **configuration posture**. It is not a vulnerability scanner, not a
rootkit detector, and not a substitute for patching. It won't tell you that your
kernel has a known CVE; it will tell you that your Redis is listening on
`0.0.0.0` with no firewall, which is how most boxes actually get taken.

## Licence

MIT
