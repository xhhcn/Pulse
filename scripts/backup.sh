#!/usr/bin/env bash
# pulse-backup -- grab a consistent snapshot of the Pulse bbolt database.
#
# Three modes:
#
#   1) HTTP mode (default): hits GET /api/admin/backup with an admin
#      token and streams the snapshot over the wire. Zero downtime —
#      the server stays fully responsive throughout the transfer.
#      Works across hosts too, so you can run this from your laptop or
#      from the NEW server and pull the file directly. It does NOT
#      matter whether the source server runs in Docker or as a
#      systemd-managed binary — the endpoint is the same.
#
#   2) File mode (--mode docker): stops the docker-compose container,
#      copies the raw metrics.db file out of the host-side Docker
#      volume, starts the container again. Used when you don't have
#      an admin token handy. Requires local Docker access.
#
#   3) File mode (--mode systemd): stops the pulse-server systemd unit,
#      copies /opt/pulse/data/metrics.db out, starts the service again.
#      Used on standalone-binary installs.
#
# Environment / flags:
#   SERVER_URL=http://HOST:PORT   target server (default: http://localhost:8008)
#   PASSWORD=<admin password>     admin password; script will auto-login
#   TOKEN=<admin token>           admin token for HTTP mode (skips the login step)
#   OUTPUT=<path>                 output path; defaults to ./pulse-backup-<utc>.db
#
# If neither PASSWORD nor TOKEN is supplied in HTTP mode, the script
# prompts interactively for the admin password (hidden input).
#
# Examples:
#   ./scripts/backup.sh                                          # HTTP, local server, prompt
#   ./scripts/backup.sh --server https://old:8008 --password xxx
#   TOKEN=abc SERVER_URL=https://old:8008 ./scripts/backup.sh
#   ./scripts/backup.sh --mode docker                            # stop-copy-start (docker)
#   ./scripts/backup.sh --mode systemd                           # stop-copy-start (systemd)
#   ./scripts/backup.sh --mode systemd --data-dir /opt/pulse/data -o /tmp/foo.db

set -euo pipefail

SERVER_URL="${SERVER_URL:-http://localhost:8008}"
TOKEN="${TOKEN:-}"
PASSWORD="${PASSWORD:-}"
OUTPUT="${OUTPUT:-}"
MODE="http"
COMPOSE_DIR="."
DATA_DIR=""
SERVICE_NAME="pulse-server"
INSTALL_DIR="/opt/pulse"

usage() {
  sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)          MODE="$2"; shift 2 ;;
    --file)          MODE="docker"; shift ;;       # legacy alias
    --http)          MODE="http"; shift ;;
    --server)        SERVER_URL="$2"; shift 2 ;;
    --token)         TOKEN="$2"; shift 2 ;;
    --password)      PASSWORD="$2"; shift 2 ;;
    --output|-o)     OUTPUT="$2"; shift 2 ;;
    --compose-dir)   COMPOSE_DIR="$2"; shift 2 ;;
    --data-dir)      DATA_DIR="$2"; shift 2 ;;
    --service)       SERVICE_NAME="$2"; shift 2 ;;
    --install-dir)   INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)       usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

# login_for_token: POSTs the admin password to /api/auth/login and
# echoes the resulting token on stdout (empty on failure, with the
# reason logged to stderr). Kept as a shell helper so callers can
# compose it with -e / pipes.
#
# SECURITY: the password is piped to curl on stdin (--data @-) rather
# than passed as a command-line argument, so it never appears in the
# `ps` output of this host. Only the running user (or root) can see
# stdin of another process; the whole world can see argv.
login_for_token() {
  local url="$1" pw="$2"
  # JSON-encode the password: escape \ and " (the two characters that
  # break a JSON string literal). Intentionally keep this minimal — we
  # avoid jq so the script works on a fresh VPS with only curl.
  local escaped="${pw//\\/\\\\}"
  escaped="${escaped//\"/\\\"}"
  local body
  if ! body="$(printf '{"password":"%s"}' "$escaped" | curl -4 -fsS \
      --retry 2 --retry-delay 1 \
      -H 'Content-Type: application/json' \
      --data-binary @- \
      "${url%/}/api/auth/login")"; then
    echo "login failed (is the URL reachable? is the password correct?)" >&2
    return 1
  fi
  # Server returns {"token":"…","expiresAt":…}. Pull out token with a
  # single sed; good enough for this well-known response shape.
  local tok
  tok="$(printf '%s' "$body" | sed -nE 's/.*"token"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p')"
  if [[ -z "$tok" ]]; then
    echo "login succeeded but response missing token: $body" >&2
    return 1
  fi
  printf '%s' "$tok"
}

# warn_if_plaintext: print a one-line warning to stderr when a non-
# localhost URL is served over plain HTTP. Credentials / snapshots
# travelling over an untrusted network in the clear is the single most
# common self-inflicted wound in a migration, so it deserves a nudge.
warn_if_plaintext() {
  local url="$1"
  local host
  host="$(printf '%s' "$url" | sed -nE 's#^https?://([^/:]+).*#\1#p')"
  if [[ "$url" == http://* ]]; then
    case "$host" in
      localhost|127.0.0.1|::1|"") ;;
      *) echo "⚠️  Using plaintext HTTP over a network link — the admin password and the full database snapshot will cross the wire unencrypted. Prefer https:// or an SSH tunnel." >&2 ;;
    esac
  fi
}

detect_docker_data_dir() {
  local cid source
  while IFS= read -r cid; do
    [[ -z "$cid" ]] && continue
    source="$(docker inspect "$cid" --format '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || true)"
    if [[ -n "$source" ]]; then
      printf '%s\n' "$source"
      return 0
    fi
  done < <(docker compose ps -q 2>/dev/null || true)
  return 1
}

TS="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$OUTPUT" ]]; then
  OUTPUT="pulse-backup-${TS}.db"
fi

case "$MODE" in
  http)
    warn_if_plaintext "$SERVER_URL"
    # Preferred credential order: explicit TOKEN > explicit PASSWORD >
    # interactive prompt for the password. We never ask for a raw
    # token interactively — tokens are 44-char base64, unpleasant to
    # type by hand, and not what a human operator actually has lying
    # around. A password is what the UI login form takes, so mirror
    # that expectation here.
    #
    # SECURITY CAVEAT: passing --password on the command line leaks the
    # password to any other user on this host through `ps`. For hands-
    # on use, prefer the interactive prompt (no args) or the PASSWORD
    # env var. The --password flag remains for automation on trusted
    # hosts where that trade-off is acceptable.
    if [[ -z "$TOKEN" && -z "$PASSWORD" ]]; then
      echo -n "Admin password for ${SERVER_URL} (hidden): " >&2
      read -rs PASSWORD
      echo >&2
    fi
    if [[ -z "$TOKEN" && -n "$PASSWORD" ]]; then
      echo "→ Logging in to ${SERVER_URL} to obtain an admin token" >&2
      if ! TOKEN="$(login_for_token "$SERVER_URL" "$PASSWORD")"; then
        exit 2
      fi
      unset PASSWORD
    fi
    if [[ -z "$TOKEN" ]]; then
      echo "error: need --password or --token for http mode" >&2
      exit 2
    fi
    echo "→ Pulling snapshot from ${SERVER_URL}/api/admin/backup" >&2
    # Pre-create the output file with 0600 so the backup never spends a
    # moment on disk world-readable. curl's default umask is 022 → 0644,
    # which is the wrong default for a file that contains the admin
    # password hash and every per-system secret.
    ( umask 077 && : > "$OUTPUT" )
    # -f: fail on 4xx/5xx
    # --retry / --retry-connrefused: survive a transient 502 during a
    # container restart on the source host.
    # The admin token is a live credential: feed the header through stdin
    # (-H @-) rather than argv, which every local user can read in ps.
    http_code="$(printf 'Authorization: Bearer %s\n' "$TOKEN" | curl -4 -fsS \
      --retry 3 --retry-delay 2 --retry-connrefused \
      -H @- \
      -o "$OUTPUT" \
      -w '%{http_code}' \
      "${SERVER_URL}/api/admin/backup")"
    if [[ "$http_code" != "200" ]]; then
      echo "error: backup endpoint returned HTTP ${http_code}" >&2
      rm -f "$OUTPUT"
      exit 3
    fi
    unset TOKEN
    ;;
  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo "error: docker not found; cannot run in --mode docker" >&2
      exit 4
    fi
    cd "$COMPOSE_DIR"
    if [[ -z "$DATA_DIR" ]]; then
      if [[ ! -f docker-compose.yaml && ! -f docker-compose.yml ]]; then
        echo "error: no docker-compose.y(a)ml in $(pwd); use --data-dir or --compose-dir" >&2
        exit 5
      fi
      if ! DATA_DIR="$(detect_docker_data_dir)"; then
        compose_file="docker-compose.yaml"
        [[ -f docker-compose.yml && ! -f docker-compose.yaml ]] && compose_file="docker-compose.yml"
        DATA_DIR="$(awk '
          /volumes:/ {in_v=1; next}
          in_v && /^[[:space:]]*-[[:space:]]/ {
            line=$0
            sub(/^[[:space:]]*-[[:space:]]+/, "", line)
            if (match(line, /:\/app\/data(:|$)/)) {
              host=substr(line, 1, RSTART-1)
              print host; exit
            }
          }
          in_v && /^[^[:space:]]/ {in_v=0}
        ' "$compose_file")"
      fi
      if [[ -z "$DATA_DIR" ]]; then
        echo "error: could not auto-detect host data directory; pass --data-dir" >&2
        exit 5
      fi
    fi
    if [[ ! -f "$DATA_DIR/metrics.db" ]]; then
      echo "error: $DATA_DIR/metrics.db does not exist" >&2
      exit 6
    fi
    echo "→ Stopping pulse container for clean flush" >&2
    docker compose stop
    echo "→ Copying $DATA_DIR/metrics.db → $OUTPUT" >&2
    ( umask 077 && cp "$DATA_DIR/metrics.db" "$OUTPUT" )
    echo "→ Restarting pulse container" >&2
    docker compose start
    ;;
  systemd)
    if ! command -v systemctl >/dev/null 2>&1; then
      echo "error: systemctl not found; cannot run in --mode systemd" >&2
      exit 4
    fi
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "error: --mode systemd needs root (re-run with sudo)" >&2
      exit 8
    fi
    [[ -z "$DATA_DIR" ]] && DATA_DIR="$INSTALL_DIR/data"
    if [[ ! -f "$DATA_DIR/metrics.db" ]]; then
      echo "error: $DATA_DIR/metrics.db does not exist" >&2
      exit 6
    fi
    echo "→ Stopping $SERVICE_NAME for clean flush" >&2
    systemctl stop "$SERVICE_NAME"
    echo "→ Copying $DATA_DIR/metrics.db → $OUTPUT" >&2
    ( umask 077 && cp "$DATA_DIR/metrics.db" "$OUTPUT" )
    echo "→ Restarting $SERVICE_NAME" >&2
    systemctl start "$SERVICE_NAME"
    ;;
  *)
    echo "error: unknown mode: $MODE (expected http|docker|systemd)" >&2
    exit 1
    ;;
esac

# Belt-and-braces: regardless of which mode wrote the file, make sure
# its mode is 0600 before we hand it off. Protects against a curl build
# that doesn't honour the pre-umask'd empty file, or a cp on a filesystem
# that drops permissions.
chmod 600 "$OUTPUT" 2>/dev/null || true

size="$(wc -c <"$OUTPUT" | tr -d ' ')"
if [[ "$size" -lt 4096 ]]; then
  echo "error: backup file is suspiciously small (${size} bytes)" >&2
  exit 7
fi

# bbolt files carry the magic number 0xEDDA0CED at offset 16 of the
# meta page. A cheap check here catches a corrupted or truncated
# download immediately rather than at restore time.
magic_hex="$(dd if="$OUTPUT" bs=1 skip=16 count=4 status=none | od -An -tx1 | tr -d ' \n')"
if [[ "$magic_hex" != "edda0ced" ]]; then
  echo "warning: bbolt magic not found at offset 16 (saw $magic_hex); the file may be corrupt" >&2
fi

echo "✓ Wrote $OUTPUT (${size} bytes, mode 0600)"
echo "  Next step — restore on the new host:"
echo "    ./scripts/restore.sh $OUTPUT          # auto-detects docker vs systemd"
echo "    ./scripts/restore.sh --mode systemd $OUTPUT   # force binary install"
