#!/usr/bin/env bash
# 50-secrets.sh — credentials sitting where they should not be.
#
# The failure mode this catches is mundane and extremely common: a .env with
# 0644, a private key in a web root, an API token pasted into shell history.

section "Secrets & Credentials"

# ── SEC-001: world-readable .env files ──────────────────────────────────────
# A .env is the default home for database passwords and API keys in Laravel,
# Node, and Django deployments. Mode 0644 means every local account can read it.
env_scan_roots=(/var/www /srv /opt /home)
loose_env=""
for root in "${env_scan_roots[@]}"; do
    [[ -d $root ]] || continue
    while IFS= read -r f; do
        mode=$(file_mode "$f")
        # Any read bit for group or other.
        if [[ -n $mode ]] && (( (10#$mode & 044) != 0 )); then
            loose_env+="$f($mode) "
        fi
    done < <(find "$root" -maxdepth 4 -name '.env' -type f 2>/dev/null | head -50)
done

if [[ -z $loose_env ]]; then
    pass SEC-001 "No group- or world-readable .env files found"
else
    fail SEC-001 "Readable .env file(s) found" \
         "chmod 600: $loose_env"
fi

# ── SEC-002: private keys under a web-served directory ──────────────────────
# A key under a document root can be one misconfigured location block away from
# being downloadable over HTTP.
web_keys=""
for root in /var/www /srv/http /usr/share/nginx; do
    [[ -d $root ]] || continue
    while IFS= read -r f; do
        # Match the PEM header rather than the extension: keys get renamed.
        if head -c 200 "$f" 2>/dev/null | grep -q 'PRIVATE KEY'; then
            web_keys+="$f "
        fi
    done < <(find "$root" -maxdepth 5 -type f \
               \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name '*.p12' \) \
               2>/dev/null | head -30)
done

if [[ -z $web_keys ]]; then
    pass SEC-002 "No private keys found under web-served directories"
else
    fail SEC-002 "Private key material inside a web root" \
         "$web_keys — move outside the document root; one bad location block makes these downloadable"
fi

# ── SEC-003: credentials in shell history ───────────────────────────────────
# Tokens pasted onto a command line persist in history and get read by anything
# that can read the user's home directory — including backup jobs.
# Patterns are prefix-anchored to well-known token formats to limit noise.
hist_hits=0
hist_users=""
token_re='(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})'

while IFS=: read -r user _ uid _ _ home _; do
    [[ $uid -ge 1000 || $user == "root" ]] || continue
    for hf in "$home/.bash_history" "$home/.zsh_history"; do
        [[ -r $hf ]] || continue
        n=$(grep -cE "$token_re" "$hf" 2>/dev/null || true)
        if [[ ${n:-0} -gt 0 ]]; then
            hist_hits=$(( hist_hits + n ))
            hist_users+="$user "
        fi
    done
done < /etc/passwd

if [[ $hist_hits -eq 0 ]]; then
    pass SEC-003 "No API tokens matched in shell history"
else
    fail SEC-003 "$hist_hits credential-shaped string(s) in shell history for: $hist_users" \
         "Revoke and rotate those credentials, then clear the history files — a token in history is a token that leaked"
fi

# ── SEC-004: private key files without a passphrase ─────────────────────────
# An unencrypted key is a single file-read away from being usable. Encrypted
# PEM keys carry a "Proc-Type: 4,ENCRYPTED" header or use the OPENSSH format
# with a KDF; we detect the plainly-unencrypted classic PEM case.
naked_keys=""
while IFS=: read -r user _ uid _ _ home _; do
    [[ $uid -ge 1000 || $user == "root" ]] || continue
    for k in "$home"/.ssh/id_*; do
        [[ -f $k && $k != *.pub ]] || continue
        if head -3 "$k" 2>/dev/null | grep -q 'BEGIN RSA PRIVATE KEY' \
           && ! head -5 "$k" 2>/dev/null | grep -q 'ENCRYPTED'; then
            naked_keys+="${user}:${k##*/} "
        fi
    done
done < /etc/passwd

if [[ -z $naked_keys ]]; then
    pass SEC-004 "No unencrypted classic-PEM private keys found"
else
    warn SEC-004 "Passphrase-less private key(s): $naked_keys" \
         "Add a passphrase with: ssh-keygen -p -f <key>  — otherwise a file read is a full credential theft"
fi
