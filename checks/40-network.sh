#!/usr/bin/env bash
# 40-network.sh — listening surface, firewall posture, and kernel network flags.

section "Network"

# ── NET-001: services listening on all interfaces ───────────────────────────
# A service bound to 0.0.0.0 is reachable from anywhere the routing table
# allows. Databases and caches in particular should be on 127.0.0.1 unless
# there is a deliberate reason and a firewall in front.
if have ss; then
    listeners=$(ss -lntuH 2>/dev/null | awk '{ print $5 }' | grep -E '^(0\.0\.0\.0|\*|\[::\]):' | sort -u)
elif have netstat; then
    listeners=$(netstat -lntu 2>/dev/null | awk 'NR>2 { print $4 }' | grep -E '^(0\.0\.0\.0|::):' | sort -u)
else
    listeners=""
fi

if [[ -z $listeners ]] && ! have ss && ! have netstat; then
    skip NET-001 "Listening socket inventory" "neither ss nor netstat available"
elif [[ -z $listeners ]]; then
    pass NET-001 "No services bound to all interfaces"
else
    count=$(printf '%s\n' "$listeners" | grep -c . || true)
    ports=$(printf '%s\n' "$listeners" | sed 's/.*://' | sort -un | tr '\n' ' ')
    warn NET-001 "$count socket(s) bound to all interfaces" \
         "Ports: $ports — confirm each is meant to be publicly reachable"
fi

# ── NET-002: high-risk services exposed publicly ────────────────────────────
# These carry data stores or admin surfaces that should essentially never face
# the internet directly.
declare -A RISKY=(
    [3306]="MySQL/MariaDB" [5432]="PostgreSQL"  [6379]="Redis"
    [27017]="MongoDB"      [9200]="Elasticsearch" [11211]="Memcached"
    [2375]="Docker API (unencrypted)" [5984]="CouchDB" [7474]="Neo4j"
)
exposed=""
for port in "${!RISKY[@]}"; do
    if printf '%s\n' "$listeners" | grep -qE ":$port$"; then
        exposed+="${RISKY[$port]}:$port "
    fi
done

if [[ -z $exposed ]]; then
    pass NET-002 "No high-risk data services bound to all interfaces"
else
    fail NET-002 "Data service(s) exposed on all interfaces: $exposed" \
         "Bind to 127.0.0.1 or restrict with firewall rules — these are scanned for continuously"
fi

# ── NET-003: firewall present and active ────────────────────────────────────
fw_state="none"
if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    fw_state="ufw (active)"
elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q running; then
    fw_state="firewalld (running)"
elif have nft && [[ -n $(nft list ruleset 2>/dev/null) ]]; then
    fw_state="nftables (rules present)"
elif have iptables && is_root; then
    rule_count=$(iptables -S 2>/dev/null | grep -cvE '^-P|^$' || true)
    [[ ${rule_count:-0} -gt 0 ]] && fw_state="iptables ($rule_count rules)"
fi

if [[ $fw_state == "none" ]]; then
    fail NET-003 "No active host firewall detected" \
         "Every listening port is reachable from anywhere routing permits — enable ufw, firewalld, or nftables"
else
    pass NET-003 "Host firewall is active: $fw_state"
fi

# ── NET-004: IP forwarding on a non-router ──────────────────────────────────
# Enabled by Docker and by VPN gateways legitimately; on a plain application
# server it lets the box be used as a pivot into the rest of the network.
if [[ -r /proc/sys/net/ipv4/ip_forward ]]; then
    fwd=$(cat /proc/sys/net/ipv4/ip_forward)
    if [[ $fwd == "0" ]]; then
        pass NET-004 "IP forwarding is disabled"
    elif have docker || [[ -d /sys/class/net/docker0 ]]; then
        skip NET-004 "IP forwarding is enabled" "expected — Docker networking requires it"
    else
        warn NET-004 "IP forwarding is enabled on a non-router host" \
             "Allows this host to route traffic between networks — a useful pivot for an attacker"
    fi
else
    skip NET-004 "IP forwarding check" "/proc/sys not readable"
fi

# ── NET-005: kernel network hardening flags ─────────────────────────────────
declare -A SYSCTL_EXPECT=(
    ["net.ipv4.conf.all.accept_redirects"]=0
    ["net.ipv4.conf.all.send_redirects"]=0
    ["net.ipv4.conf.all.accept_source_route"]=0
    ["net.ipv4.tcp_syncookies"]=1
    ["net.ipv4.conf.all.rp_filter"]=1
)
bad=""
checked=0
for key in "${!SYSCTL_EXPECT[@]}"; do
    path="/proc/sys/${key//./\/}"
    [[ -r $path ]] || continue
    (( checked++ ))
    actual=$(cat "$path" 2>/dev/null)
    [[ $actual == "${SYSCTL_EXPECT[$key]}" ]] || bad+="$key=$actual (want ${SYSCTL_EXPECT[$key]}) "
done

# Distinguish "all flags correct" from "no flags readable at all" — otherwise a
# host without /proc/sys reports a vacuous pass.
if [[ $checked -eq 0 ]]; then
    skip NET-005 "Kernel network hardening flags" "no sysctl entries readable on this host"
elif [[ -z $bad ]]; then
    pass NET-005 "Kernel network hardening flags are set correctly"
else
    warn NET-005 "Kernel network flags differ from hardened defaults" \
         "$bad — set these in /etc/sysctl.d/ and apply with sysctl --system"
fi
