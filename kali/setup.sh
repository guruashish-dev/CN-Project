#!/usr/bin/env bash
set -euo pipefail

echo "[+] Building Kali scanner image"
docker build -t autovuln-kali -f kali/dockerfile kali

echo "[+] Starting kali_scanner container"
docker rm -f kali_scanner >/dev/null 2>&1 || true
docker run -d --name kali_scanner autovuln-kali sleep infinity

echo "[+] Validating tools"
docker exec kali_scanner which nmap nikto whatweb wapiti
