#!/usr/bin/env bash
# ==============================================================================
# SecureScan 1-Click Launch & Quick Tunnel Script (Option A)
# ==============================================================================

set -euo pipefail

echo -e "\033[1;36m==========================================================\033[0m"
echo -e "\033[1;36m  SecureScan 1-Click Launch (Option A - Cloudflare Tunnel)\033[0m"
echo -e "\033[1;36m==========================================================\033[0m"
echo ""

# Verify Docker daemon is accessible
if ! docker info > /dev/null 2>&1; then
    echo -e "\033[1;31m[ERROR] Docker is not running. Please start Docker first.\033[0m"
    exit 1
fi

echo -e "\033[1;33m[1/3] Building and starting SecureScan containers with Cloudflare Quick Tunnel...\033[0m"
docker compose --profile tunnel up --build -d

echo -e "\033[1;33m[2/3] Waiting for Cloudflare Tunnel to establish public HTTPS route...\033[0m"
TUNNEL_URL=""
for i in {1..15}; do
    sleep 2
    LOGS=$(docker compose logs tunnel 2>&1 || true)
    if echo "$LOGS" | grep -q "trycloudflare.com"; then
        TUNNEL_URL=$(echo "$LOGS" | grep -o 'https://[a-zA-Z0-9-]\+\.trycloudflare\.com' | head -n 1)
        if [ -n "$TUNNEL_URL" ]; then
            break
        fi
    fi
    echo -e "  Waiting for tunnel route... ($((i*2))/30 s)"
done

echo ""
echo -e "\033[1;32m[3/3] SecureScan Platform is LIVE!\033[0m"
echo -e "\033[0;37m----------------------------------------------------------\033[0m"
if [ -n "$TUNNEL_URL" ]; then
    echo -e "  \033[1;32mPublic HTTPS Tunnel URL : $TUNNEL_URL\033[0m"
else
    echo -e "  \033[1;33mPublic Tunnel           : Check with 'docker compose logs tunnel'\033[0m"
fi
echo -e "  Local Frontend Dashboard: http://localhost:3000"
echo -e "  Local Backend REST API  : http://localhost:8000/api/health"
echo -e "  Interactive Swagger Docs: http://localhost:8000/docs"
echo -e "\033[0;37m----------------------------------------------------------\033[0m"
echo ""
echo -e "\033[1;35mTip: Use 'tests/fixtures/valid_vulnerable.zip' for testing the dashboard.\033[0m"
echo -e "\033[0;37mTo stop the stack: docker compose --profile tunnel down\033[0m"
