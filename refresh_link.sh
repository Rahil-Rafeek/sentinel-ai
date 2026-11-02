#!/bin/bash
set -e

PROJECT_DIR="/Users/rahil/.gemini/antigravity-ide/scratch/ticket-token-system/backend/app/core/sentinel-ai"
cd "$PROJECT_DIR"

echo "=== Refreshing Sentinel AI Tunnel Link ==="

# 1. Kill stale cloudflared processes
killall -9 cloudflared 2>/dev/null || true
pkill -9 -f "cloudflared tunnel" 2>/dev/null || true
sleep 1

# 2. Check if FastAPI backend is alive on port 8000
if ! lsof -i :8000 >/dev/null 2>&1; then
    echo "Starting FastAPI server on port 8000..."
    nohup python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 > ./server.log 2>&1 &
    sleep 3
else
    echo "FastAPI server is active on port 8000."
fi

# 3. Clear previous tunnel log
rm -f ./sentinel_tunnel.log

# 4. Start fresh Cloudflare tunnel
CLOUDFLARED_BIN="/Users/rahil/.local/bin/cloudflared"
if [ ! -x "$CLOUDFLARED_BIN" ]; then
    CLOUDFLARED_BIN="./bin/cloudflared"
fi

echo "Launching fresh Cloudflare Tunnel..."
nohup "$CLOUDFLARED_BIN" tunnel --url http://127.0.0.1:8000 > ./sentinel_tunnel.log 2>&1 &
CF_PID=$!

# 5. Poll for the new URL (up to 15 seconds)
NEW_URL=""
for i in {1..15}; do
    sleep 1
    NEW_URL=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' ./sentinel_tunnel.log 2>/dev/null | tail -n 1 || true)
    if [ -n "$NEW_URL" ]; then
        break
    fi
done

if [ -z "$NEW_URL" ]; then
    echo "Cloudflare tunnel did not produce a URL in 15s. Checking log:"
    cat ./sentinel_tunnel.log
    exit 1
fi

# 6. Update LIVE_URLS.txt
cat <<EOF > ./LIVE_URLS.txt
==============================================================
🛡️  SENTINEL AI — ACTIVE SHAREABLE LINKS
Updated: $(date)
==============================================================

🔗 Primary (Cloudflare Edge):
   $NEW_URL

🔗 Local Direct:
   http://localhost:8000

Backend Health: http://127.0.0.1:8000/api/v1/system/health
Status: OPERATIONAL
==============================================================
EOF

echo ""
echo "=========================================================="
echo "🛡️  NEW FRESH LINK GENERATED:"
echo "👉 $NEW_URL"
echo "=========================================================="

