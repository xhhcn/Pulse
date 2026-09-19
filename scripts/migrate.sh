#!/usr/bin/env bash
# pulse-migrate -- one-shot migration from an old Pulse server to this host.
#
# Run this on the NEW server, after you've installed Pulse on it (via
# install-pulse-server.sh for the standalone binary, or `docker compose
# up -d` for Docker). It:
#
#   1. Logs in to the OLD server with the admin password you supply
#      (or a token, if you have one).
#   2. Pulls a consistent hot-snapshot of the OLD server's database
#      via GET /api/admin/backup — no downtime on the old server.
#   3. Verifies the snapshot (size + bbolt magic number) to catch a
#      bad transfer before anything destructive runs.
#   4. Stops the local Pulse process (auto-detects docker vs
#      systemd), preserves the existing metrics.db as
#      metrics.db.pre-restore-<utc> so rollback is one command,
#      swaps the snapshot in, and starts the service again.
#   5. Polls /healthz until the new instance is live.
#
# Usage:
#   sudo ./scripts/migrate.sh --from http://OLD_HOST:8008
#   sudo ./scripts/migrate.sh --from http://OLD_HOST:8008 --password 'YourPW'
#   sudo ./scripts/migrate.sh --from http://OLD_HOST:8008 --token  'TOKEN'
#   sudo ./scripts/migrate.sh --from http://OLD_HOST:8008 --mode systemd -y
#   sudo ./scripts/migrate.sh --from http://OLD_HOST:8008 --keep-backup snapshot.db
#
# Flags (all optional unless noted):
#   --from URL          old server base URL (required)
#   --password PW       admin password of the old server (prompted if omitted)
#   --token  TOK        admin token of the old server (skips login step)
#   --mode   MODE       docker | systemd | auto (default: auto)
#   --compose-dir DIR   docker-compose dir for the NEW host (default: cwd)
#   --data-dir    DIR   override target metrics.db directory
#   --port   PORT       health-check port on the NEW host (default: 8008)
#   --service NAME      systemd unit name (default: pulse-server)
#   --install-dir DIR   standalone install dir (default: /opt/pulse)
#   --keep-backup FILE  keep the downloaded snapshot at this path
#                       (default: delete after successful restore)
#   -y, --yes           non-interactive, skip the confirmation prompt
#   -h, --help          show this help

set -euo pipefail

FROM=""
# Honour inherited env vars — an operator who does
#   export PASSWORD='...'
#   sudo -E migrate.sh --from http://old:8008 -y
# quite reasonably expects the password to be picked up without also
# having to pass --password. Using `${PASSWORD:-}` (instead of `""`)
# preserves the caller's value while still giving us a sensible default
# when the env var is unset.
PASSWORD="${PASSWORD:-}"
TOKEN="${TOKEN:-}"
MODE="auto"
COMPOSE_DIR="."
DATA_DIR=""
PORT=""
SERVICE_NAME="pulse-server"
INSTALL_DIR="/opt/pulse"
KEEP_BACKUP=""
YES="false"

# Resolve to the real script dir even when invoked through a symlink
# (e.g. /usr/local/bin/pulse-migrate → /opt/pulse/scripts/migrate.sh),
# because backup.sh and restore.sh live next to this script.
resolve_script_dir() {
  local src="${BASH_SOURCE[0]}"
  while [[ -L "$src" ]]; do
    local dir
    dir="$(cd -P "$(dirname "$src")" >/dev/null 2>&1 && pwd)"
    src="$(readlink "$src")"
    [[ "$src" != /* ]] && src="$dir/$src"
  done
  cd -P "$(dirname "$src")" >/dev/null 2>&1 && pwd
}
SCRIPT_DIR="$(resolve_script_dir)"

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)          FROM="$2"; shift 2 ;;
    --password)      PASSWORD="$2"; shift 2 ;;
    --token)         TOKEN="$2"; shift 2 ;;
    --mode)          MODE="$2"; shift 2 ;;
    --compose-dir)   COMPOSE_DIR="$2"; shift 2 ;;
    --data-dir)      DATA_DIR="$2"; shift 2 ;;
    --port)          PORT="$2"; shift 2 ;;
    --service)       SERVICE_NAME="$2"; shift 2 ;;
    --install-dir)   INSTALL_DIR="$2"; shift 2 ;;
    --keep-backup)   KEEP_BACKUP="$2"; shift 2 ;;
    -y|--yes)        YES="true"; shift ;;
    -h|--help)       usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

if [[ -z "$FROM" ]]; then
  echo "error: --from <OLD_SERVER_URL> is required" >&2
  usage
fi
FROM="${FROM%/}"

# Warn if the link between new host and old host is plaintext. The
# snapshot file contains the admin password hash and every per-system
# secret — sending it over unencrypted HTTP across the internet is a
# terrible idea, even briefly. Localhost is fine (for testing).
case "$FROM" in
  http://localhost*|http://127.0.0.1*|'http://[::1]'*) ;;
  http://*)
    echo "⚠️  --from is plaintext HTTP. The admin password and the full DB snapshot" >&2
    echo "    (including the password hash and every per-system secret) will cross" >&2
    echo "    the network unencrypted. Prefer https:// or an SSH tunnel, e.g.:" >&2
    echo "        ssh -fN -L 8008:localhost:8008 user@OLD_HOST" >&2
    echo "        sudo $0 --from http://localhost:8008 ..." >&2
    if [[ "$YES" != "true" ]]; then
      read -r -p "    Continue anyway? [y/N] " ans
      case "$ans" in y|Y|yes|YES) ;; *) echo "aborted."; exit 0 ;; esac
    fi
    ;;
esac

# Unified cleanup: every temp dir we create (snapshot staging,
# bootstrap download dir) gets tracked in CLEANUP_DIRS and mopped up
# on EXIT. Dir-level cleanup is strictly enough to nuke the snapshot
# file too, so we don't need a separate CLEANUP_FILE path.
CLEANUP_DIRS=()
cleanup_on_exit() {
  local d
  for d in "${CLEANUP_DIRS[@]}"; do
    [[ -n "$d" && -d "$d" ]] && rm -rf "$d"
  done
}
trap cleanup_on_exit EXIT

# Self-bootstrap: migrate.sh normally ships alongside backup.sh and
# restore.sh (installed by install-pulse-server.sh or cloned from the
# repo), but we also want a single-file experience for the Docker path
# where users grab just migrate.sh with one curl. If the sidecars
# aren't next to us, fetch them from the same branch of the repo into
# a private temp dir and use them from there. Zero-effort for the
# user, and the downloaded copies are cleaned up on exit.
if [[ ! -x "$SCRIPT_DIR/backup.sh" || ! -x "$SCRIPT_DIR/restore.sh" ]]; then
  base="${PULSE_SCRIPT_BASE:-https://raw.githubusercontent.com/xhhcn/Pulse/main/scripts}"
  # The fetched scripts run as root: only accept an https:// source so a
  # mirror override cannot be a plaintext URL that an on-path party rewrites.
  case "$base" in
    https://*) ;;
    *) echo "error: PULSE_SCRIPT_BASE must be an https:// URL (got: $base)" >&2; exit 10 ;;
  esac
  echo "→ helper scripts not found next to $0 — fetching from $base" >&2
  boot="$(mktemp -d "${TMPDIR:-/tmp}/pulse-migrate-boot.XXXXXX")"
  chmod 700 "$boot"
  CLEANUP_DIRS+=( "$boot" )
  for s in backup.sh restore.sh; do
    if ! curl -fsSL --proto '=https' --retry 2 --retry-delay 1 -o "$boot/$s" "$base/$s"; then
      echo "error: failed to download $s from $base" >&2
      echo "       (set PULSE_SCRIPT_BASE to a mirror, or pre-install the scripts)" >&2
      exit 10
    fi
    chmod +x "$boot/$s"
  done
  SCRIPT_DIR="$boot"
fi

# Resolve an output path for the snapshot. If the caller wants to keep
# the file they named it; otherwise we stage it in a private temp dir
# (added to CLEANUP_DIRS) so a failed migration doesn't leave stray
# copies of the secret-bearing DB file lying around.
if [[ -n "$KEEP_BACKUP" ]]; then
  SNAPSHOT="$KEEP_BACKUP"
else
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/pulse-migrate.XXXXXX")"
  chmod 700 "$tmpdir"
  SNAPSHOT="$tmpdir/pulse-migrate.db"
  CLEANUP_DIRS+=( "$tmpdir" )
fi

echo "──────────────────────────────────────────────"
echo " Pulse migration"
echo "──────────────────────────────────────────────"
echo "  source   : $FROM"
echo "  mode     : $MODE (auto-detected if 'auto')"
echo "  snapshot : $SNAPSHOT"
echo

if [[ "$YES" != "true" ]]; then
  read -r -p "This will replace the local metrics.db. Continue? [y/N] " ans
  case "$ans" in y|Y|yes|YES) ;; *) echo "aborted."; exit 0 ;; esac
fi

# Step 1 + 2: pull the snapshot. We delegate to backup.sh so there is
# exactly one code path that touches /api/admin/backup (retries, bbolt
# magic check, error handling, etc.).
#
# SECURITY: never put the password/token on the backup.sh argv. The
# shell's `ps` output is world-readable on most hosts, and an operator
# running `ps -ef` in another terminal would see the plaintext secret
# for as long as backup.sh is alive. backup.sh already reads the
# PASSWORD / TOKEN env vars (see backup.sh `${PASSWORD:-}` default), so
# we export them into the child's environment instead — only the
# process's own /proc/<pid>/environ is readable, and only by uid 0 or
# the same user, which is a meaningful step up from world-readable
# argv.
args=( --mode http --server "$FROM" --output "$SNAPSHOT" )

echo "→ step 1/2 : fetching snapshot from $FROM"
if ! PASSWORD="$PASSWORD" TOKEN="$TOKEN" "$SCRIPT_DIR/backup.sh" "${args[@]}"; then
  echo "error: snapshot download failed" >&2
  exit 3
fi
# Scrub the secrets from this shell's environment as soon as the
# child has finished — they are no longer needed, and if the caller
# re-used this shell later the leftover PASSWORD in `env` would be a
# footgun.
unset PASSWORD TOKEN

# Step 3 + 4 + 5: restore locally. restore.sh handles mode auto-detect,
# the pre-restore backup of the existing DB, and the /healthz polling.
echo
echo "→ step 2/2 : restoring snapshot onto this host"
rargs=( -y "$SNAPSHOT" --mode "$MODE" --compose-dir "$COMPOSE_DIR" )
[[ -n "$DATA_DIR" ]] && rargs+=( --data-dir "$DATA_DIR" )
[[ -n "$PORT"     ]] && rargs+=( --port     "$PORT"     )
rargs+=( --service "$SERVICE_NAME" --install-dir "$INSTALL_DIR" )

if ! "$SCRIPT_DIR/restore.sh" "${rargs[@]}"; then
  # On restore failure, rescue the already-downloaded snapshot out of
  # the temp dir (which EXIT will delete) so the operator can investigate
  # or re-run the restore manually without repeating the network pull.
  rescue_dir="${HOME:-/root}"
  rescue="$rescue_dir/pulse-migrate-rescue-$(date -u +%Y%m%dT%H%M%SZ).db"
  echo "error: restore failed." >&2
  if ( umask 077 && cp "$SNAPSHOT" "$rescue" ) 2>/dev/null; then
    chmod 600 "$rescue" 2>/dev/null || true
    echo "       Snapshot preserved at: $rescue  (0600)" >&2
    echo "       To retry restore once you've fixed the cause:" >&2
    echo "           sudo pulse-restore -y $rescue         # if pulse-restore is on PATH" >&2
    echo "           # or re-run this migrate command with --keep-backup $rescue" >&2
  else
    echo "       Could not save the snapshot out of the temp dir." >&2
    echo "       Re-run with --keep-backup ./pulse-backup.db next time." >&2
  fi
  exit 4
fi

echo
echo "✓ Migration complete."
echo "  Old host is unchanged — it still has the original DB, and you"
echo "  can keep using it as a read-only reference until you've"
echo "  confirmed the new host works."
echo
echo "  Next steps on each monitored client (only if the SERVER URL"
echo "  actually changed — if you use DNS + a reverse proxy, nothing"
echo "  needs updating):"
echo "    sudo sed -i 's#$FROM##g' /etc/systemd/system/pulse-client.service  # remove old"
echo "    # then edit the Environment=... line to point at the new URL"
echo "    sudo systemctl daemon-reload && sudo systemctl restart pulse-client"
