#!/bin/bash
# SENTINEL AI - Tunnel Watchdog & Auto-Healer
# Automatically detects tunnel drops/expirations and re-establishes connections

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

LOG_FILE="./watchdog.log"
STATUS_FILE="./LIVE_URLS.txt"

echo "[$(date)] Watchdog service started." >> "$LOG_FILE"

CLOUDFLARED_BIN="/Users/rahil/.local/bin/cloudflared"
if [ ! -x "$CLOUDFLARED_BIN" ]; then
    CLOUDFLARED_BIN="./bin/cloudflared"
fi

while true; do
    # 1. Verify FastAPI is listening on 8000
    if ! lsof -i :8000 >/dev/null 2>&1; then
        echo "[$(date)] FastAPI server not detected on port 8000. Restarting..." >> "$LOG_FILE"
        nohup python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 > ./server.log 2>&1 &
        sleep 2
    fi

    # 2. Check Cloudflare tunnel health
    CF_HEALTH=$(tail -n 30 ./sentinel_tunnel.log 2>/dev/null | grep -E "Unauthorized: Tunnel not found|Serve tunnel error|panic" || true)
    CF_RUNNING=$(pgrep -f "cloudflared tunnel --url http://127.0.0.1:8000" || true)

    if [ -n "$CF_HEALTH" ] || [ -z "$CF_RUNNING" ]; then
        echo "[$(date)] Cloudflare tunnel dropped or expired. Refreshing..." >> "$LOG_FILE"
        pkill -f "cloudflared tunnel --url http://127.0.0.1:8000" 2>/dev/null || true
        rm -f ./sentinel_tunnel.log
        nohup "$CLOUDFLARED_BIN" tunnel --url http://127.0.0.1:8000 > ./sentinel_tunnel.log 2>&1 &
        sleep 4
    fi

    # 3. Extract active URLs and update LIVE_URLS.txt
    CF_URL=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' ./sentinel_tunnel.log 2>/dev/null | tail -n 1)
    
    cat <<EOF > "$STATUS_FILE"
==============================================================
🛡️  SENTINEL AI — ACTIVE SHAREABLE LINKS
Updated: $(date)
==============================================================

🔗 Primary (Cloudflare Edge):
   $CF_URL

🔗 Alternative (SSH Direct):
   https://da695c8c0f3278.lhr.life

Backend Health: http://127.0.0.1:8000/api/v1/system/health
Status: OPERATIONAL
==============================================================
EOF

    # Sleep 20 seconds before next heartbeat check
    sleep 20
done
