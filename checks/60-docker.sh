#!/usr/bin/env bash
# 60-docker.sh — container host exposure.
#
# Docker's failure modes are mostly about the boundary being thinner than people
# assume: the daemon socket is root-equivalent, and a --privileged container is
# not meaningfully contained at all.

section "Docker"

if ! have docker && [[ ! -S /var/run/docker.sock ]]; then
    skip DOC-000 "Docker checks" "docker not installed on this host"
    # shellcheck disable=SC2317  # reachable via source; shellcheck cannot see that
    return 0 2>/dev/null || exit 0
fi

# ── DOC-001: daemon socket permissions ──────────────────────────────────────
# Write access to docker.sock is root on the host, full stop: you can start a
# container that bind-mounts / and chroot into it. Membership of the docker
# group is therefore equivalent to passwordless sudo, which is worth stating
# plainly because it is very often granted casually.
if [[ -S /var/run/docker.sock ]]; then
    sock_mode=$(file_mode /var/run/docker.sock)
    if [[ -n $sock_mode ]] && (( (10#$sock_mode & 006) != 0 )); then
        fail DOC-001 "docker.sock is world-accessible ($sock_mode)" \
             "Any local user can start a privileged container and become root on the host"
    else
        docker_members=$(awk -F: '$1 == "docker" { print $4 }' /etc/group 2>/dev/null)
        if [[ -n $docker_members ]]; then
            warn DOC-001 "docker group members: $docker_members" \
                 "Docker group membership is root-equivalent — treat it as you would passwordless sudo"
        else
            pass DOC-001 "docker.sock is not world-accessible and the docker group is empty"
        fi
    fi
else
    skip DOC-001 "docker.sock permissions" "socket not present"
fi

# ── DOC-002: daemon exposed over TCP ────────────────────────────────────────
# An unauthenticated 2375/2376 listener is remote root. These get found by
# internet-wide scanners within hours of being exposed.
if have ss; then
    if ss -lntH 2>/dev/null | awk '{print $4}' | grep -qE ':(2375|2376)$'; then
        fail DOC-002 "Docker daemon is listening on TCP (2375/2376)" \
             "Unless mTLS is enforced this is unauthenticated remote root — bind to the unix socket instead"
    else
        pass DOC-002 "Docker daemon is not listening on TCP"
    fi
else
    skip DOC-002 "Docker TCP listener check" "ss not available"
fi

# ── The remaining checks need to talk to the daemon ─────────────────────────
if ! docker info >/dev/null 2>&1; then
    skip DOC-003 "Running container inspection" "cannot reach the docker daemon (needs root or docker group)"
    # shellcheck disable=SC2317  # reachable via source; shellcheck cannot see that
    return 0 2>/dev/null || exit 0
fi

# ── DOC-003: privileged containers ──────────────────────────────────────────
# --privileged disables seccomp, AppArmor, and capability dropping, and hands
# the container every device. Escaping it is a documented one-liner.
privileged=$(docker ps --quiet 2>/dev/null | while read -r cid; do
    [[ -n $cid ]] || continue
    if [[ $(docker inspect -f '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null) == "true" ]]; then
        docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||'
    fi
done | tr '\n' ' ')

if [[ -z ${privileged// /} ]]; then
    pass DOC-003 "No containers are running with --privileged"
else
    fail DOC-003 "Privileged container(s): $privileged" \
         "A privileged container is not a security boundary — escaping to the host is trivial"
fi

# ── DOC-004: containers mounting the docker socket ──────────────────────────
# The classic CI-agent pattern. A container with the socket mounted can start a
# sibling container with any mount it likes, which is host root.
sock_mounts=$(docker ps --quiet 2>/dev/null | while read -r cid; do
    [[ -n $cid ]] || continue
    if docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null | grep -q 'docker.sock'; then
        docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||'
    fi
done | tr '\n' ' ')

if [[ -z ${sock_mounts// /} ]]; then
    pass DOC-004 "No containers have the docker socket mounted"
else
    fail DOC-004 "Container(s) mounting docker.sock: $sock_mounts" \
         "These can start sibling containers with arbitrary mounts — equivalent to host root"
fi

# ── DOC-005: containers running as root ─────────────────────────────────────
# Not an escape on its own, but it removes the last layer between a compromised
# process and a namespace escape, and it is trivially avoidable with USER.
root_containers=$(docker ps --quiet 2>/dev/null | while read -r cid; do
    [[ -n $cid ]] || continue
    user=$(docker inspect -f '{{.Config.User}}' "$cid" 2>/dev/null)
    if [[ -z $user || $user == "root" || $user == "0" ]]; then
        docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||'
    fi
done | tr '\n' ' ')

if [[ -z ${root_containers// /} ]]; then
    pass DOC-005 "No containers are running as root"
else
    count=$(printf '%s' "$root_containers" | wc -w | tr -d ' ')
    warn DOC-005 "$count container(s) running as root: $root_containers" \
         "Set USER in the Dockerfile — a process that escapes its namespace escapes as whatever it was running as"
fi

# ── DOC-006: unrestricted inter-container traffic ───────────────────────────
# On the default bridge every container can reach every other container's
# ports, including ones never published to the host.
icc=$(docker network inspect bridge -f '{{index .Options "com.docker.network.bridge.enable_icc"}}' 2>/dev/null)
if [[ $icc == "false" ]]; then
    pass DOC-006 "Inter-container communication is disabled on the default bridge"
else
    warn DOC-006 "Inter-container communication is unrestricted on the default bridge" \
         "Any container can reach any other container's ports — use user-defined networks to segment"
fi
