#!/usr/bin/env bash
set -euo pipefail

SET4="wk_tracker_bans_v4"
SET6="wk_tracker_bans_v6"

usage() {
  cat <<'EOF'
Usage:
  tracker-fw.sh ensure
  tracker-fw.sh apply <ip> [--ban-id N] [--reason TEXT]
  tracker-fw.sh clear <ip> [--ban-id N] [--reason TEXT]
EOF
}

need_bin() { command -v "$1" >/dev/null 2>&1 || { echo "$1 required" >&2; exit 1; }; }

canon_ip() {
  python3 - <<'PY' "$1"
import ipaddress, sys
print(ipaddress.ip_address(sys.argv[1].strip()))
PY
}

ensure_rules() {
  ipset create "$SET4" hash:ip family inet  hashsize 1024 maxelem 262144 -exist
  ipset create "$SET6" hash:ip family inet6 hashsize 1024 maxelem 262144 -exist

  iptables  -C INPUT -m set --match-set "$SET4" src -j DROP 2>/dev/null || \
  iptables  -I INPUT 1 -m set --match-set "$SET4" src -j DROP

  ip6tables -C INPUT -m set --match-set "$SET6" src -j DROP 2>/dev/null || \
  ip6tables -I INPUT 1 -m set --match-set "$SET6" src -j DROP
}

ACTION="${1:-}"
[[ -n "$ACTION" ]] || { usage; exit 2; }
shift || true

need_bin ipset
need_bin iptables
need_bin ip6tables

case "$ACTION" in
  ensure)
    ensure_rules
    echo "ok action=ensure detail=ipset_sets_ready input_drop_hooks_ready"
    ;;
  apply|clear)
    IP="${1:-}"
    [[ -n "$IP" ]] || { usage; exit 2; }
    shift || true

    BAN_ID="0"
    REASON="none"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --ban-id) BAN_ID="${2:-0}"; shift 2 ;;
        --reason) REASON="${2:-none}"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
      esac
    done

    IP_CANON="$(canon_ip "$IP")"
    if [[ "$IP_CANON" == *:* ]]; then
      TARGET_SET="$SET6"
    else
      TARGET_SET="$SET4"
    fi

    if [[ "$ACTION" == "apply" ]]; then
      ipset add "$TARGET_SET" "$IP_CANON" -exist
    else
      ipset del "$TARGET_SET" "$IP_CANON" 2>/dev/null || true
    fi

    echo "ok action=$ACTION ip=$IP_CANON set=$TARGET_SET ban_id=$BAN_ID reason=$REASON"
    ;;
  *)
    usage
    exit 2
    ;;
esac
