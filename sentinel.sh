#!/usr/bin/env bash
# sentinel.sh — Linux server hardening auditor.
#
# Read-only by design: every check inspects state and reports. Nothing here
# writes to the system, restarts a service, or edits a config file. That is a
# deliberate constraint — an auditor you cannot trust to be inert is an auditor
# you will not run on production.
#
# Usage:
#   ./sentinel.sh                        # human-readable report
#   ./sentinel.sh --format json          # machine-readable, for CI
#   ./sentinel.sh --only ssh,network     # run a subset
#   ./sentinel.sh --fail-on warn         # exit non-zero on warnings too
#
# Exit codes:
#   0  no findings at or above the --fail-on threshold
#   1  findings at or above the threshold
#   2  usage error

set -uo pipefail

readonly SENTINEL_VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly CHECK_DIR="$SCRIPT_DIR/checks"

SENTINEL_FORMAT="text"
FAIL_ON="fail"
ONLY_FILTER=""

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)
            SENTINEL_FORMAT=${2:-}
            [[ $SENTINEL_FORMAT =~ ^(text|json)$ ]] || {
                printf 'sentinel: --format must be text or json\n' >&2; exit 2; }
            shift 2 ;;
        --only)
            ONLY_FILTER=${2:-}
            [[ -n $ONLY_FILTER ]] || { printf 'sentinel: --only needs a value\n' >&2; exit 2; }
            shift 2 ;;
        --fail-on)
            FAIL_ON=${2:-}
            [[ $FAIL_ON =~ ^(fail|warn)$ ]] || {
                printf 'sentinel: --fail-on must be fail or warn\n' >&2; exit 2; }
            shift 2 ;;
        --version) printf 'sentinel-audit %s\n' "$SENTINEL_VERSION"; exit 0 ;;
        -h|--help) usage 0 ;;
        *) printf 'sentinel: unknown argument: %s\n' "$1" >&2; usage 2 ;;
    esac
done

export SENTINEL_FORMAT

# shellcheck source=lib/core.sh
source "$SCRIPT_DIR/lib/core.sh"

# ── Host banner ─────────────────────────────────────────────────────────────
os_name=$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-unknown}")
os_name=${os_name:-$(uname -s)}

if [[ $SENTINEL_FORMAT == "text" ]]; then
    printf '%ssentinel-audit %s%s  %s%s%s\n' \
        "$C_BOLD" "$SENTINEL_VERSION" "$C_RESET" "$C_DIM" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$C_RESET"
    printf '%shost:%s %s   %sos:%s %s   %sprivilege:%s %s\n' \
        "$C_DIM" "$C_RESET" "$(hostname)" \
        "$C_DIM" "$C_RESET" "$os_name" \
        "$C_DIM" "$C_RESET" "$([[ $EUID -eq 0 ]] && echo root || echo "non-root (some checks will be skipped)")"
fi

# ── Run checks ──────────────────────────────────────────────────────────────
# Modules are numbered so they run in a deliberate order: the most
# externally-exposed surface (SSH, network) before local hygiene.
shopt -s nullglob
for check in "$CHECK_DIR"/*.sh; do
    name=$(basename "$check" .sh)
    name=${name#*-}                      # strip the ordering prefix

    if [[ -n $ONLY_FILTER && ",$ONLY_FILTER," != *",$name,"* ]]; then
        continue
    fi

    # Each module runs in the current shell so it can accumulate results, but a
    # module that fails must not abort the whole audit — a broken check should
    # cost you that check, not the report.
    # shellcheck source=/dev/null
    source "$check" || warn "RUN-${name}" "Check module '$name' exited with an error" \
                            "The remaining modules still ran; this module's results may be incomplete"
done
shopt -u nullglob

# ── Report ──────────────────────────────────────────────────────────────────
if [[ $SENTINEL_FORMAT == "json" ]]; then
    printf '{\n'
    printf '  "version": "%s",\n' "$SENTINEL_VERSION"
    printf '  "host": "%s",\n' "$(json_escape "$(hostname)")"
    printf '  "os": "%s",\n' "$(json_escape "$os_name")"
    printf '  "timestamp": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "privileged": %s,\n' "$([[ $EUID -eq 0 ]] && echo true || echo false)"
    printf '  "summary": { "pass": %d, "fail": %d, "warn": %d, "skip": %d },\n' \
        "$SENTINEL_PASS" "$SENTINEL_FAIL" "$SENTINEL_WARN" "$SENTINEL_SKIP"
    printf '  "findings": [\n'
    for i in "${!SENTINEL_ROWS[@]}"; do
        printf '    %s' "${SENTINEL_ROWS[$i]}"
        [[ $i -lt $(( ${#SENTINEL_ROWS[@]} - 1 )) ]] && printf ','
        printf '\n'
    done
    printf '  ]\n}\n'
else
    total=$(( SENTINEL_PASS + SENTINEL_FAIL + SENTINEL_WARN ))
    printf '\n%s─────────────────────────────────────────────%s\n' "$C_DIM" "$C_RESET"
    printf '%s%d passed%s   %s%d failed%s   %s%d warnings%s   %s%d skipped%s\n' \
        "$C_GREEN" "$SENTINEL_PASS" "$C_RESET" \
        "$C_RED" "$SENTINEL_FAIL" "$C_RESET" \
        "$C_YELLOW" "$SENTINEL_WARN" "$C_RESET" \
        "$C_DIM" "$SENTINEL_SKIP" "$C_RESET"

    if [[ $total -gt 0 ]]; then
        score=$(( SENTINEL_PASS * 100 / total ))
        printf 'score: %s%d%%%s of applicable checks passed\n' "$C_BOLD" "$score" "$C_RESET"
    fi
    [[ $SENTINEL_SKIP -gt 0 && $EUID -ne 0 ]] && \
        printf '%shint: re-run with sudo to include the %d privileged checks%s\n' \
            "$C_DIM" "$SENTINEL_SKIP" "$C_RESET"
fi

# ── Exit status ─────────────────────────────────────────────────────────────
if [[ $FAIL_ON == "warn" ]]; then
    (( SENTINEL_FAIL + SENTINEL_WARN > 0 )) && exit 1
else
    (( SENTINEL_FAIL > 0 )) && exit 1
fi
exit 0
