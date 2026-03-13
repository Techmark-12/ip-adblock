<<<<<<< HEAD
# ip-adblock
=======
# GoBlock DNS AdBlocker

A custom DNS adblocker service running on Render.com with DNS-over-HTTPS (DoH) support.

## Features

- **DNS-over-HTTPS (DoH)**: Secure DNS queries over HTTPS
- **Blocklist Management**: Auto-updating blocklists from multiple sources
- **Web Dashboard**: Real-time statistics and management
- **Router Compatible**: Works with IP-only routers via local DNS forwarder

## API Endpoints

- `GET /health` - Health check
- `GET /` - Web dashboard
- `GET /dns-query` - DoH endpoint (GET/POST)
- `GET /api/stats` - Service statistics
- `POST /api/block` - Block a domain
- `DELETE /api/block/:domain` - Unblock a domain
- `POST /api/update-blocklists` - Force blocklist update

## Router Setup

Since your router only accepts IP addresses, run a local DNS forwarder:

```bash
# Install cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64
sudo mv cloudflared-linux-amd64 /usr/local/bin/cloudflared

# Run DNS proxy to your Render DoH
sudo cloudflared proxy-dns --port 53 --upstream https://your-service-name.onrender.com/dns-query
>>>>>>> f5c6ef4 (Initial commit: GoBlock DNS adblocker)
