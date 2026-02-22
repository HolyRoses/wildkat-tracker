#!/bin/bash
# ─────────────────────────────────────────────────────────────
# wildkat-tracker auto-deploy script
# Run via cron as the ubuntu user to detect pushes to main and deploy updates.
# Only restarts the tracker if tracker_server.py actually changed.
#
# Crontab entry (checks every 5 minutes):
#   */5 * * * * /opt/tracker/deploy.sh >> /var/log/tracker-deploy.log 2>&1
# ─────────────────────────────────────────────────────────────

# ── Configuration ────────────────────────────────────────────
REPO_DIR="/home/ubuntu/wildkat-tracker"       # local clone of the repo
REPO_BRANCH="main"                             # branch to track
DEPLOY_FILE="tracker_server.py"               # file to deploy from repo
DEPLOY_DEST="/opt/tracker/tracker_server.py"  # destination on server
SERVICE_NAME="tracker"                         # systemd service to restart
LOCK_FILE="/tmp/tracker-deploy.lock"           # prevent concurrent runs

# ─────────────────────────────────────────────────────────────

set -euo pipefail

TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

# ── Prevent concurrent runs ───────────────────────────────────
if [ -e "$LOCK_FILE" ]; then
    echo "[$TIMESTAMP] Deploy already in progress, skipping."
    exit 0
fi
touch "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

# ── Move into repo ────────────────────────────────────────────
cd "$REPO_DIR"

# ── Fetch latest from remote (no merge yet) ───────────────────
git fetch origin "$REPO_BRANCH" --quiet

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/$REPO_BRANCH")"

if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
    # No changes at all — exit silently
    exit 0
fi

# ── Repo has changed — pull it ────────────────────────────────
echo "[$TIMESTAMP] Changes detected on $REPO_BRANCH — pulling"
echo "[$TIMESTAMP]   local:  $LOCAL_SHA"
echo "[$TIMESTAMP]   remote: $REMOTE_SHA"

git pull origin "$REPO_BRANCH" --quiet

NEW_SHA="$(git rev-parse HEAD)"
echo "[$TIMESTAMP] Updated to $NEW_SHA"

# ── Check if tracker_server.py actually changed ───────────────
MD5_REPO="$(md5sum "$REPO_DIR/$DEPLOY_FILE" | awk '{print $1}')"
MD5_LIVE="$(md5sum "$DEPLOY_DEST"           | awk '{print $1}')"

if [ "$MD5_REPO" = "$MD5_LIVE" ]; then
    echo "[$TIMESTAMP] $DEPLOY_FILE unchanged — no restart needed"
    exit 0
fi

echo "[$TIMESTAMP] $DEPLOY_FILE changed (md5 $MD5_LIVE → $MD5_REPO)"

# ── Syntax check before deploying ────────────────────────────
if ! python3 -c "import ast; ast.parse(open('$REPO_DIR/$DEPLOY_FILE').read())"; then
    echo "[$TIMESTAMP] ERROR: $DEPLOY_FILE failed syntax check — aborting deploy"
    exit 1
fi

# ── Deploy ────────────────────────────────────────────────────
echo "[$TIMESTAMP] Deploying $DEPLOY_FILE → $DEPLOY_DEST"
sudo cp "$REPO_DIR/$DEPLOY_FILE" "$DEPLOY_DEST"
sudo chown tracker:tracker "$DEPLOY_DEST"
sudo chmod 755 "$DEPLOY_DEST"

# ── Restart service ───────────────────────────────────────────
echo "[$TIMESTAMP] Restarting $SERVICE_NAME..."
sudo systemctl restart "$SERVICE_NAME"

# ── Verify service came back up ───────────────────────────────
sleep 2
if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "[$TIMESTAMP] $SERVICE_NAME is running — deploy successful"
else
    echo "[$TIMESTAMP] ERROR: $SERVICE_NAME failed to start after deploy"
    exit 1
fi
