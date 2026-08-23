#!/usr/bin/env bash
# core.sh — shared runtime for sentinel-audit checks.
#
# Every check module sources nothing directly; the runner sources this file
# first, so checks can assume `pass`, `fail`, `warn`, `skip` and `section` exist.

# ── Terminal capability detection ───────────────────────────────────────────
# Colour only when stdout is a TTY and the terminal advertises colour support,
# so piping to a file or a CI log yields clean, greppable text.
if [[ -t 1 ]] && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    readonly C_RESET=$'\033[0m'
    readonly C_BOLD=$'\033[1m'
    readonly C_DIM=$'\033[2m'
    readonly C_RED=$'\033[31m'
    readonly C_GREEN=$'\033[32m'
    readonly C_YELLOW=$'\033[33m'
    readonly C_BLUE=$'\033[34m'
else
    readonly C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE=''
fi

# ── Result accumulators ─────────────────────────────────────────────────────
declare -gi SENTINEL_PASS=0
declare -gi SENTINEL_FAIL=0
declare -gi SENTINEL_WARN=0
declare -gi SENTINEL_SKIP=0

# JSON result rows, assembled incrementally so a run that dies partway through
# still leaves a valid partial report behind.
declare -ga SENTINEL_ROWS=()

# Populated by the runner before each check module is sourced.
SENTINEL_CURRENT_SECTION="general"

# json_escape <string>
# Escapes the characters JSON forbids in a string literal. Bash has no native
# JSON encoder and we refuse to depend on jq for *writing* output, since the
# whole point is that this runs on a bare, freshly-provisioned box.
json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

# _record <status> <id> <title> <detail>
_record() {
    local status=$1 id=$2 title=$3 detail=${4:-}
    SENTINEL_ROWS+=("$(printf '{"section":"%s","id":"%s","status":"%s","title":"%s","detail":"%s"}' \
        "$(json_escape "$SENTINEL_CURRENT_SECTION")" \
        "$(json_escape "$id")" \
        "$status" \
        "$(json_escape "$title")" \
        "$(json_escape "$detail")")")
}

section() {
    SENTINEL_CURRENT_SECTION=$1
    [[ $SENTINEL_FORMAT == "text" ]] && printf '\n%s▸ %s%s\n' "$C_BOLD$C_BLUE" "$1" "$C_RESET"
    return 0
}

pass() {
    local id=$1 title=$2
    (( SENTINEL_PASS++ ))
    _record pass "$id" "$title" ""
    [[ $SENTINEL_FORMAT == "text" ]] && printf '  %s✓%s %s %s%s%s\n' \
        "$C_GREEN" "$C_RESET" "$title" "$C_DIM" "[$id]" "$C_RESET"
    return 0
}

fail() {
    local id=$1 title=$2 detail=${3:-}
    (( SENTINEL_FAIL++ ))
    _record fail "$id" "$title" "$detail"
    if [[ $SENTINEL_FORMAT == "text" ]]; then
        printf '  %s✗%s %s %s%s%s\n' "$C_RED$C_BOLD" "$C_RESET" "$title" "$C_DIM" "[$id]" "$C_RESET"
        [[ -n $detail ]] && printf '      %s%s%s\n' "$C_DIM" "$detail" "$C_RESET"
    fi
    return 0
}

warn() {
    local id=$1 title=$2 detail=${3:-}
    (( SENTINEL_WARN++ ))
    _record warn "$id" "$title" "$detail"
    if [[ $SENTINEL_FORMAT == "text" ]]; then
        printf '  %s!%s %s %s%s%s\n' "$C_YELLOW" "$C_RESET" "$title" "$C_DIM" "[$id]" "$C_RESET"
        [[ -n $detail ]] && printf '      %s%s%s\n' "$C_DIM" "$detail" "$C_RESET"
    fi
    return 0
}

# skip marks a check as not-applicable (missing service, wrong distro, no root).
# Skips are deliberately *not* failures: a box with no SSH daemon should not be
# penalised for its sshd config.
skip() {
    local id=$1 title=$2 reason=${3:-not applicable}
    (( SENTINEL_SKIP++ ))
    _record skip "$id" "$title" "$reason"
    [[ $SENTINEL_FORMAT == "text" ]] && printf '  %s−%s %s %s(%s)%s\n' \
        "$C_DIM" "$C_RESET" "$title" "$C_DIM" "$reason" "$C_RESET"
    return 0
}

# ── Helpers available to checks ─────────────────────────────────────────────

have() { command -v "$1" >/dev/null 2>&1; }

is_root() { [[ $EUID -eq 0 ]]; }

# sshd_option <name>
# Reads an effective sshd setting. Prefers `sshd -T`, which resolves Include
# directives and Match blocks the way the daemon actually does — grepping
# sshd_config directly misses options set in /etc/ssh/sshd_config.d/*.conf,
# which is where most modern distros put their real configuration.
sshd_option() {
    local name=${1,,}
    if is_root && have sshd; then
        sshd -T 2>/dev/null | awk -v k="$name" '$1 == k { $1=""; sub(/^ /,""); print; exit }'
    else
        awk -v k="$name" 'tolower($1) == k && $0 !~ /^[[:space:]]*#/ { $1=""; sub(/^ /,""); print; exit }' \
            /etc/ssh/sshd_config 2>/dev/null
    fi
}

# file_mode <path> — octal permission bits, portable across GNU and BSD stat.
file_mode() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}
