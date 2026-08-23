#!/usr/bin/env bash
# 20-filesystem.sh — permissions on the files that gate authentication.
#
# These are the classic local-privilege-escalation footholds: a writable
# /etc/passwd or a readable /etc/shadow turns any local shell into root.

section "Filesystem & Permissions"

# ── FS-001 / FS-002: credential file permissions ────────────────────────────
# Expected modes: /etc/passwd is world-readable by design (0644), /etc/shadow
# must never be (0640 with shadow group, or 0600).
check_mode() {
    local id=$1 path=$2 max_mode=$3 label=$4
    if [[ ! -e $path ]]; then
        skip "$id" "$label permissions" "$path not present"
        return
    fi
    local mode; mode=$(file_mode "$path")
    if [[ -z $mode ]]; then
        skip "$id" "$label permissions" "could not stat $path"
    elif (( 10#$mode <= 10#$max_mode )); then
        pass "$id" "$label is $mode (max $max_mode)"
    else
        fail "$id" "$label is too permissive: $mode" \
             "Expected $max_mode or stricter on $path — chmod $max_mode $path"
    fi
}

check_mode FS-001 /etc/passwd  644 "/etc/passwd"
check_mode FS-002 /etc/shadow  640 "/etc/shadow"
check_mode FS-003 /etc/group   644 "/etc/group"
check_mode FS-004 /etc/gshadow 640 "/etc/gshadow"

# ── FS-005: world-writable files outside the designated temp dirs ───────────
# /tmp, /var/tmp and /dev/shm are world-writable by design; anything else that
# is world-writable and not a symlink is a place an attacker can plant code.
if is_root; then
    ww_count=$(find / -xdev -type f -perm -0002 \
                 -not -path '/tmp/*' -not -path '/var/tmp/*' -not -path '/dev/shm/*' \
                 -not -path '/proc/*' -not -path '/sys/*' \
                 2>/dev/null | head -100 | wc -l | tr -d ' ')
    if [[ $ww_count -eq 0 ]]; then
        pass FS-005 "No world-writable files outside temp directories"
    else
        fail FS-005 "$ww_count world-writable file(s) found outside temp directories" \
             "Run: find / -xdev -type f -perm -0002 -not -path '/tmp/*' — any of these can be replaced by any local user"
    fi
else
    skip FS-005 "World-writable file scan" "requires root to traverse all of /"
fi

# ── FS-006: unowned files ───────────────────────────────────────────────────
# Files owned by a UID with no passwd entry are usually leftovers from a deleted
# account. If that UID is ever recycled, the new user silently inherits them.
if is_root; then
    orphan_count=$(find / -xdev \( -nouser -o -nogroup \) \
                     -not -path '/proc/*' -not -path '/sys/*' \
                     2>/dev/null | head -100 | wc -l | tr -d ' ')
    if [[ $orphan_count -eq 0 ]]; then
        pass FS-006 "No files owned by a non-existent user or group"
    else
        warn FS-006 "$orphan_count file(s) owned by a deleted user or group" \
             "A recycled UID would inherit these — reassign or remove them"
    fi
else
    skip FS-006 "Orphaned file scan" "requires root"
fi

# ── FS-007: SUID binaries outside the expected set ──────────────────────────
# SUID root binaries are the standard local-privesc surface. We do not try to
# judge each one; we report the count and the list so a human can diff it
# against a known-good baseline for the distro.
if is_root; then
    suid_list=$(find / -xdev -type f -perm -4000 \
                  -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | sort)
    suid_count=$(printf '%s\n' "$suid_list" | grep -c . || true)
    if [[ $suid_count -le 30 ]]; then
        pass FS-007 "SUID binary count is within a typical range ($suid_count)"
    else
        warn FS-007 "$suid_count SUID binaries present" \
             "Higher than a typical minimal server — review against a distro baseline"
    fi
else
    skip FS-007 "SUID binary inventory" "requires root"
fi

# ── FS-008: separate mount for /tmp ─────────────────────────────────────────
# A /tmp on its own mount can carry nosuid,nodev,noexec, which blocks the most
# common "drop a payload in /tmp and run it" step.
if mountpoint -q /tmp 2>/dev/null; then
    tmp_opts=$(awk '$2 == "/tmp" { print $4; exit }' /proc/mounts 2>/dev/null)
    missing=""
    for opt in nosuid nodev noexec; do
        [[ $tmp_opts == *"$opt"* ]] || missing+="$opt "
    done
    if [[ -z $missing ]]; then
        pass FS-008 "/tmp is a separate mount with nosuid,nodev,noexec"
    else
        warn FS-008 "/tmp is a separate mount but missing: $missing" \
             "Add the missing options in /etc/fstab to block execution from /tmp"
    fi
else
    warn FS-008 "/tmp is not a separate mount point" \
         "Cannot enforce noexec/nosuid on /tmp while it shares the root filesystem"
fi
