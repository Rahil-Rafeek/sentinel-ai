#!/bin/bash
# SENTINEL AI - Single-Command Persistent Server & Cloudflare Tunnel Runner

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=== [SENTINEL AI] Starting Persistent Production Server ==="

# 1. Kill any existing instances on port 8000 or stale tunnels
lsof -ti :8000 | xargs kill -9 2>/dev/null || true
pkill -f "cloudflared tunnel --url http://127.0.0.1:8000" 2>/dev/null || true

# 2. Build production frontend if not built
if [ ! -d "frontend/dist" ]; then
    echo "Building frontend production bundle..."
    cd frontend && npm run build && cd ..
fi

# 3. Start unified FastAPI server (serves React SPA + API + WebSockets)
echo "Starting FastAPI server on port 8000..."
nohup python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 > ./server.log 2>&1 &
UVICORN_PID=$!
echo "Uvicorn running (PID: $UVICORN_PID)"

sleep 2

# 4. Start Cloudflare Quick Tunnel
echo "Establishing Cloudflare Tunnel..."
CLOUDFLARED_BIN="/Users/rahil/.local/bin/cloudflared"
if [ ! -x "$CLOUDFLARED_BIN" ]; then
    CLOUDFLARED_BIN="./bin/cloudflared"
fi

nohup "$CLOUDFLARED_BIN" tunnel --url http://127.0.0.1:8000 > ./sentinel_tunnel.log 2>&1 &
CLOUDFLARED_PID=$!
echo "Cloudflared running (PID: $CLOUDFLARED_PID)"

echo "Waiting for tunnel URL..."
sleep 4
TUNNEL_URL=$(grep -o 'https://[a-zA-Z0-9.-]*\.trycloudflare\.com' ./sentinel_tunnel.log | head -n 1)

echo ""
echo "=========================================================="
echo "🛡️  SENTINEL AI IS LIVE & SHAREABLE GLOBALLY!"
echo "🔗  URL: $TUNNEL_URL"
echo "=========================================================="
echo "Logs available at ./server.log and ./sentinel_tunnel.log"
