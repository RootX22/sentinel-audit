#!/usr/bin/env bash
# 10-ssh.sh — SSH daemon exposure checks.
#
# SSH is the single most-attacked service on an internet-facing Linux box, so
# these run first. Every check reads the *effective* config via sshd -T where
# possible (see sshd_option in lib/core.sh) rather than grepping sshd_config,
# because sshd_config.d drop-ins routinely override the main file.

section "SSH"

if [[ ! -f /etc/ssh/sshd_config ]]; then
    skip SSH-000 "SSH daemon configuration" "no sshd_config on this host"
    return 0 2>/dev/null || exit 0
fi

# ── SSH-001: root login ─────────────────────────────────────────────────────
# "prohibit-password" (key-only root) is accepted: plenty of provisioning
# tooling legitimately needs it, and it is not password-guessable.
permit_root=$(sshd_option permitrootlogin)
case ${permit_root,,} in
    no)
        pass SSH-001 "Root login over SSH is disabled" ;;
    prohibit-password|without-password)
        warn SSH-001 "Root login permitted with keys only" \
             "PermitRootLogin=$permit_root — acceptable, but a named sudo user is preferable for audit trails" ;;
    yes)
        fail SSH-001 "Root login over SSH is permitted with a password" \
             "Set 'PermitRootLogin no' in sshd_config — this is the primary target of SSH brute-force botnets" ;;
    *)
        # Unset means the compiled-in default, which is prohibit-password on
        # OpenSSH >= 7.0 but 'yes' on much older builds. Flag rather than guess.
        warn SSH-001 "PermitRootLogin is not set explicitly" \
             "Relying on the compiled default; set it explicitly to make intent auditable" ;;
esac

# ── SSH-002: password authentication ────────────────────────────────────────
pw_auth=$(sshd_option passwordauthentication)
if [[ ${pw_auth,,} == "no" ]]; then
    pass SSH-002 "Password authentication is disabled"
else
    fail SSH-002 "Password authentication is enabled" \
         "Set 'PasswordAuthentication no' and deploy keys — passwords are credential-stuffable, keys are not"
fi

# ── SSH-003: empty passwords ────────────────────────────────────────────────
empty_pw=$(sshd_option permitemptypasswords)
if [[ ${empty_pw,,} == "no" || -z $empty_pw ]]; then
    pass SSH-003 "Empty passwords are rejected"
else
    fail SSH-003 "Empty passwords are accepted" \
         "PermitEmptyPasswords=yes allows login to any account with a blank password field"
fi

# ── SSH-004: listening port ─────────────────────────────────────────────────
# Moving off 22 is not a security control — it is noise reduction. Reported as
# informational so it never inflates the failure count.
ssh_port=$(sshd_option port)
ssh_port=${ssh_port:-22}
if [[ $ssh_port == "22" ]]; then
    warn SSH-004 "SSH is on the default port 22" \
         "Not a vulnerability, but a non-standard port cuts automated scan volume substantially"
else
    pass SSH-004 "SSH is on a non-default port ($ssh_port)"
fi

# ── SSH-005: protocol-level hardening ───────────────────────────────────────
max_auth=$(sshd_option maxauthtries)
if [[ -n $max_auth && $max_auth -le 4 ]]; then
    pass SSH-005 "MaxAuthTries is restrictive ($max_auth)"
else
    warn SSH-005 "MaxAuthTries is permissive (${max_auth:-default 6})" \
         "Lower to 3-4 so a single connection cannot cycle through many credentials"
fi

# ── SSH-006: X11 forwarding on a server ─────────────────────────────────────
x11=$(sshd_option x11forwarding)
if [[ ${x11,,} == "no" || -z $x11 ]]; then
    pass SSH-006 "X11 forwarding is disabled"
else
    warn SSH-006 "X11 forwarding is enabled" \
         "Rarely needed on a server and widens the trust boundary to the client's X display"
fi

# ── SSH-007: host key permissions ───────────────────────────────────────────
# A world-readable private host key lets any local user impersonate the server
# and silently MITM every future SSH session to it.
weak_keys=""
for key in /etc/ssh/ssh_host_*_key; do
    [[ -f $key ]] || continue
    mode=$(file_mode "$key")
    # Anything granting group or other any bit at all is too open.
    if [[ -n $mode && ${mode: -2} != "00" ]]; then
        weak_keys+="${key##*/} ($mode) "
    fi
done

if [[ -z $weak_keys ]]; then
    pass SSH-007 "SSH host private keys are not group/world readable"
else
    fail SSH-007 "SSH host private keys have overly broad permissions" \
         "chmod 600: $weak_keys"
fi
