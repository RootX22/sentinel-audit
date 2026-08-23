#!/usr/bin/env bash
# 30-accounts.sh — account hygiene: who can log in, and how.

section "Accounts & Authentication"

# ── ACC-001: additional UID 0 accounts ──────────────────────────────────────
# Any account with UID 0 *is* root, whatever it is called. A second one is
# either a deliberate (bad) convenience or a backdoor.
uid0=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null | tr '\n' ' ')
uid0_count=$(printf '%s' "$uid0" | wc -w | tr -d ' ')

if [[ $uid0_count -eq 1 && ${uid0// /} == "root" ]]; then
    pass ACC-001 "root is the only UID 0 account"
elif [[ $uid0_count -eq 0 ]]; then
    skip ACC-001 "UID 0 account check" "could not read /etc/passwd"
else
    fail ACC-001 "Multiple UID 0 accounts exist: $uid0" \
         "Every one of these has full root authority regardless of its name"
fi

# ── ACC-002: accounts with no password set ──────────────────────────────────
# An empty second field in /etc/shadow means the account authenticates with no
# password at all — via console, su, or any PAM path that does not require one.
if is_root && [[ -r /etc/shadow ]]; then
    empty=$(awk -F: '($2 == "") { print $1 }' /etc/shadow 2>/dev/null | tr '\n' ' ')
    if [[ -z ${empty// /} ]]; then
        pass ACC-002 "No accounts have an empty password field"
    else
        fail ACC-002 "Account(s) with an empty password: $empty" \
             "Lock them with: passwd -l <user>  (or usermod -L <user>)"
    fi
else
    skip ACC-002 "Empty password check" "requires root to read /etc/shadow"
fi

# ── ACC-003: system accounts with an interactive shell ──────────────────────
# Service accounts below the login UID threshold should have nologin/false.
# A shell on one of them turns a service compromise into an interactive foothold.
login_shells='/bin/bash|/bin/sh|/bin/zsh|/bin/ksh|/usr/bin/bash|/usr/bin/zsh|/bin/dash'
sys_shell=$(awk -F: -v re="$login_shells" \
    '$3 < 1000 && $1 != "root" && $1 != "sync" && $7 ~ re { print $1 }' \
    /etc/passwd 2>/dev/null | tr '\n' ' ')

if [[ -z ${sys_shell// /} ]]; then
    pass ACC-003 "No system accounts have an interactive login shell"
else
    warn ACC-003 "System account(s) with a login shell: $sys_shell" \
         "Set to /usr/sbin/nologin unless the account genuinely needs to run interactive jobs"
fi

# ── ACC-004: password ageing policy ─────────────────────────────────────────
if [[ -f /etc/login.defs ]]; then
    max_days=$(awk '$1 == "PASS_MAX_DAYS" { print $2; exit }' /etc/login.defs 2>/dev/null)
    if [[ -n $max_days && $max_days -le 365 && $max_days -gt 0 ]]; then
        pass ACC-004 "Password maximum age is set ($max_days days)"
    else
        warn ACC-004 "Password maximum age is unset or unlimited (${max_days:-none})" \
             "Set PASS_MAX_DAYS in /etc/login.defs so long-lived credentials eventually rotate"
    fi
else
    skip ACC-004 "Password ageing policy" "/etc/login.defs not present"
fi

# ── ACC-005: passwordless sudo ──────────────────────────────────────────────
# NOPASSWD:ALL means any process running as that user escalates to root with no
# further authentication — a single RCE becomes a root RCE.
if is_root; then
    nopass=$(grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
             | grep -c 'ALL' || true)
    if [[ ${nopass:-0} -eq 0 ]]; then
        pass ACC-005 "No passwordless sudo rules granting ALL"
    else
        warn ACC-005 "$nopass passwordless sudo rule(s) granting ALL" \
             "Acceptable for automation accounts, dangerous for human ones — scope NOPASSWD to specific commands"
    fi
else
    skip ACC-005 "Sudo policy check" "requires root to read /etc/sudoers"
fi

# ── ACC-006: authorized_keys permissions ────────────────────────────────────
# A group- or world-writable authorized_keys lets another user append their own
# key and log in as its owner. sshd refuses such keys under StrictModes, so this
# usually presents as a confusing "key rejected" rather than a visible breach.
weak_ak=""
while IFS=: read -r user _ uid _ _ home _; do
    [[ $uid -ge 1000 || $user == "root" ]] || continue
    ak="$home/.ssh/authorized_keys"
    [[ -f $ak ]] || continue
    mode=$(file_mode "$ak")
    # Reject any write bit for group or other.
    if [[ -n $mode ]] && (( (10#$mode & 022) != 0 )); then
        weak_ak+="$user($mode) "
    fi
done < /etc/passwd

if [[ -z $weak_ak ]]; then
    pass ACC-006 "No group- or world-writable authorized_keys files"
else
    fail ACC-006 "Writable authorized_keys for: $weak_ak" \
         "chmod 600 — another user can append their own key and assume these accounts"
fi
