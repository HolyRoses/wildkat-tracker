#!/usr/bin/env bash
set -euo pipefail

BASE_URL="https://tracker.example.net"
COUNT=10
INTERVAL="0.10"
TIMEOUT=10
LOGIN_USER="probe-user"
LOGIN_PASSWORD="wrong-password"
WEBAUTHN_USER="probe-user"
TFA_USER="probe-user"
TFA_PASSWORD="wrong-password"
TFA_BAD_CODE="000000"
DO_404=0
DO_POST=0
DO_LOGIN_FAIL=0
DO_WEBAUTHN_FAIL=0
DO_TFA_FAIL=0
DO_ALL=0
INSECURE=0
CACERT=""
RESOLVE_ARG=""
VERBOSE=0

usage() {
  cat <<'EOF'
Usage:
  ./security_event_trigger.sh [trigger flags] [options]

Trigger flags (choose one or more):
  --404            Trigger repeated GET 404s.
  --post           Trigger repeated unknown POSTs (404 on POST path).
  --login-fail     Trigger repeated failed login attempts.
  --webauthn-fail  Trigger repeated WebAuthn auth-start failures.
  --tfa-fail       Trigger repeated failed TFA challenge attempts (requires valid login creds).
  --all            Run all trigger types in sequence.

Common options:
  --base URL              Base URL (default: https://tracker.example.net)
  --count N               Number of requests per trigger (default: 10)
  --interval SEC          Sleep between requests (default: 0.10)
  --timeout SEC           Curl max time in seconds (default: 10)
  --username USER         Username for --login-fail (default: probe-user)
  --password PASS         Password for --login-fail (default: wrong-password)
  --webauthn-user USER    Username for --webauthn-fail (default: probe-user)
  --tfa-user USER         Username for --tfa-fail login (default: probe-user)
  --tfa-password PASS     Password for --tfa-fail login (default: wrong-password)
  --tfa-code CODE         Bad TFA code to submit repeatedly (default: 000000)
  --insecure              Pass -k to curl (skip TLS verification)
  --cacert FILE           Custom CA bundle for curl
  --resolve HOST:PORT:IP  Curl --resolve override (useful for sandbox)
  --verbose               Print per-request result lines
  -h, --help              Show this help

Examples:
  ./security_event_trigger.sh --404 --count 12 --interval 0.05
  ./security_event_trigger.sh --post --base https://tracker.example.net
  ./security_event_trigger.sh --login-fail --username thomas --count 8
  ./security_event_trigger.sh --webauthn-fail --webauthn-user no_such_user --count 12
  ./security_event_trigger.sh --tfa-fail --tfa-user thomas --tfa-password 'correct-password' --count 8
  ./security_event_trigger.sh --all --insecure --base https://127.0.0.1:18444
  ./security_event_trigger.sh --404 --cacert /tmp/wk-sandbox-ca/rootCA.crt \
    --resolve tracker.example.net:18444:127.0.0.1 --base https://tracker.example.net:18444
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --404) DO_404=1; shift ;;
    --post) DO_POST=1; shift ;;
    --login-fail) DO_LOGIN_FAIL=1; shift ;;
    --webauthn-fail) DO_WEBAUTHN_FAIL=1; shift ;;
    --tfa-fail) DO_TFA_FAIL=1; shift ;;
    --all) DO_ALL=1; shift ;;
    --base) BASE_URL="${2:-}"; shift 2 ;;
    --count) COUNT="${2:-}"; shift 2 ;;
    --interval) INTERVAL="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    --username) LOGIN_USER="${2:-}"; shift 2 ;;
    --password) LOGIN_PASSWORD="${2:-}"; shift 2 ;;
    --webauthn-user) WEBAUTHN_USER="${2:-}"; shift 2 ;;
    --tfa-user) TFA_USER="${2:-}"; shift 2 ;;
    --tfa-password) TFA_PASSWORD="${2:-}"; shift 2 ;;
    --tfa-code) TFA_BAD_CODE="${2:-}"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --cacert) CACERT="${2:-}"; shift 2 ;;
    --resolve) RESOLVE_ARG="${2:-}"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "$DO_ALL" -eq 1 ]]; then
  DO_404=1
  DO_POST=1
  DO_LOGIN_FAIL=1
  DO_WEBAUTHN_FAIL=1
  DO_TFA_FAIL=1
fi

if [[ "$DO_404" -eq 0 && "$DO_POST" -eq 0 && "$DO_LOGIN_FAIL" -eq 0 && "$DO_WEBAUTHN_FAIL" -eq 0 && "$DO_TFA_FAIL" -eq 0 ]]; then
  echo "No trigger selected. Use --404, --post, --login-fail, --webauthn-fail, --tfa-fail, or --all." >&2
  usage
  exit 2
fi

if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -le 0 ]]; then
  echo "--count must be a positive integer" >&2
  exit 2
fi

do_request() {
  local method="$1"
  local url="$2"
  local data="${3:-}"
  local content_type="${4:-}"
  local code
  local cmd=(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time "$TIMEOUT")
  if [[ "$INSECURE" -eq 1 ]]; then
    cmd+=(-k)
  fi
  if [[ -n "$CACERT" ]]; then
    cmd+=(--cacert "$CACERT")
  fi
  if [[ -n "$RESOLVE_ARG" ]]; then
    cmd+=(--resolve "$RESOLVE_ARG")
  fi
  if [[ -n "$content_type" ]]; then
    cmd+=(-H "Content-Type: ${content_type}")
  fi
  cmd+=(-X "$method")

  if [[ -n "$data" ]]; then
    code=$("${cmd[@]}" --data "$data" "$url") || code="ERR"
  else
    code=$("${cmd[@]}" "$url") || code="ERR"
  fi

  if [[ "$VERBOSE" -eq 1 ]]; then
    printf '[%s] %s %s -> %s\n' "$(date '+%H:%M:%S')" "$method" "$url" "$code"
  fi
}

run_404_burst() {
  echo "Triggering http_404_burst candidates: count=$COUNT interval=${INTERVAL}s"
  local i url
  for ((i=1; i<=COUNT; i++)); do
    url="${BASE_URL}/manage/__security_probe_404_${i}_$RANDOM"
    do_request "GET" "$url"
    sleep "$INTERVAL"
  done
}

run_unknown_post_burst() {
  echo "Triggering unknown_post_burst candidates: count=$COUNT interval=${INTERVAL}s"
  local i url payload
  for ((i=1; i<=COUNT; i++)); do
    url="${BASE_URL}/manage/__security_probe_post_${i}_$RANDOM"
    payload="p=${i}&ts=$(date +%s)"
    do_request "POST" "$url" "$payload"
    sleep "$INTERVAL"
  done
}

run_login_fail_burst() {
  echo "Triggering login_fail_burst candidates for user='$LOGIN_USER': count=$COUNT interval=${INTERVAL}s"
  local i payload
  for ((i=1; i<=COUNT; i++)); do
    payload="username=${LOGIN_USER}&password=${LOGIN_PASSWORD}-${i}"
    do_request "POST" "${BASE_URL}/manage/login" "$payload"
    sleep "$INTERVAL"
  done
}

run_webauthn_fail_burst() {
  echo "Triggering webauthn_fail_burst candidates for user='$WEBAUTHN_USER': count=$COUNT interval=${INTERVAL}s"
  local i payload
  for ((i=1; i<=COUNT; i++)); do
    payload="{\"username\":\"${WEBAUTHN_USER}\",\"all_credentials\":false}"
    do_request "POST" "${BASE_URL}/manage/webauthn/auth/start" "$payload" "application/json"
    sleep "$INTERVAL"
  done
}

run_tfa_fail_burst() {
  echo "Triggering tfa_fail_burst candidates for user='$TFA_USER': count=$COUNT interval=${INTERVAL}s (fresh login per attempt)"
  local cookie_jar headers_file challenge_page location i payload status_code csrf_token
  cookie_jar="$(mktemp)"
  headers_file="$(mktemp)"
  challenge_page="$(mktemp)"
  trap 'rm -f "$cookie_jar" "$headers_file" "$challenge_page"' RETURN

  for ((i=1; i<=COUNT; i++)); do
    : > "$cookie_jar"
    : > "$headers_file"
    : > "$challenge_page"

    local login_cmd=(curl --silent --show-error --output /dev/null --dump-header "$headers_file" --max-time "$TIMEOUT")
    if [[ "$INSECURE" -eq 1 ]]; then
      login_cmd+=(-k)
    fi
    if [[ -n "$CACERT" ]]; then
      login_cmd+=(--cacert "$CACERT")
    fi
    if [[ -n "$RESOLVE_ARG" ]]; then
      login_cmd+=(--resolve "$RESOLVE_ARG")
    fi
    login_cmd+=(-c "$cookie_jar" -X POST --data "username=${TFA_USER}&password=${TFA_PASSWORD}" "${BASE_URL}/manage/login")
    "${login_cmd[@]}" || true

    location="$(awk '/^Location:/ {print $2}' "$headers_file" | tr -d '\r' | tail -n1)"
    if [[ "$location" != *"/manage/tfa/challenge"* ]]; then
      echo "Attempt ${i}: unable to enter TFA challenge for user '$TFA_USER' (redirect=${location:-<none>})." >&2
      echo "Check valid password, account TFA state, and password-login policy." >&2
      return 1
    fi

    local challenge_cmd=(curl --silent --show-error --max-time "$TIMEOUT")
    if [[ "$INSECURE" -eq 1 ]]; then
      challenge_cmd+=(-k)
    fi
    if [[ -n "$CACERT" ]]; then
      challenge_cmd+=(--cacert "$CACERT")
    fi
    if [[ -n "$RESOLVE_ARG" ]]; then
      challenge_cmd+=(--resolve "$RESOLVE_ARG")
    fi
    challenge_cmd+=(-b "$cookie_jar" -c "$cookie_jar" -o "$challenge_page" "${BASE_URL}/manage/tfa/challenge")
    "${challenge_cmd[@]}" || true

    csrf_token="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$challenge_page" | head -n1)"
    if [[ -z "$csrf_token" ]]; then
      echo "Attempt ${i}: unable to extract CSRF token from /manage/tfa/challenge." >&2
      return 1
    fi

    payload="_csrf=${csrf_token}&code=${TFA_BAD_CODE}"
    local tfa_cmd=(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time "$TIMEOUT")
    if [[ "$INSECURE" -eq 1 ]]; then
      tfa_cmd+=(-k)
    fi
    if [[ -n "$CACERT" ]]; then
      tfa_cmd+=(--cacert "$CACERT")
    fi
    if [[ -n "$RESOLVE_ARG" ]]; then
      tfa_cmd+=(--resolve "$RESOLVE_ARG")
    fi
    tfa_cmd+=(-b "$cookie_jar" -c "$cookie_jar" -X POST --data "$payload" "${BASE_URL}/manage/tfa/challenge")
    status_code=$("${tfa_cmd[@]}") || status_code="ERR"
    if [[ "$VERBOSE" -eq 1 ]]; then
      printf '[%s] attempt=%s POST %s -> %s\n' "$(date '+%H:%M:%S')" "$i" "${BASE_URL}/manage/tfa/challenge" "$status_code"
    fi
    sleep "$INTERVAL"
  done
}

echo "Base URL: $BASE_URL"
echo "Starting security trigger run at $(date '+%Y-%m-%d %H:%M:%S')"

if [[ "$DO_404" -eq 1 ]]; then
  run_404_burst
fi
if [[ "$DO_POST" -eq 1 ]]; then
  run_unknown_post_burst
fi
if [[ "$DO_LOGIN_FAIL" -eq 1 ]]; then
  run_login_fail_burst
fi
if [[ "$DO_WEBAUTHN_FAIL" -eq 1 ]]; then
  run_webauthn_fail_burst
fi
if [[ "$DO_TFA_FAIL" -eq 1 ]]; then
  run_tfa_fail_burst
fi

echo "Completed at $(date '+%Y-%m-%d %H:%M:%S'). Check the Security tab/event log for detections."
