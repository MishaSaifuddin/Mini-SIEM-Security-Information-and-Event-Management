# Deployment

This folder is used for publicly exposing the Mini SIEM via a Cloudflare quick tunnel.

## What's here
- `cloudflared.exe` - Cloudflare Tunnel client (downloaded, git-ignored)
- `tunnel.log` - tunnel output (git-ignored)

## How to publish publicly (free, no account)

1. Start the backend (serves both the React UI and the API on one port):
   ```bash
   cd ../backend
   venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

2. Download cloudflared once:
   ```bash
   curl -L -o cloudflared.exe https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe
   ```

3. Start a quick tunnel:
   ```bash
   cloudflared tunnel --url http://127.0.0.1:8000
   ```

4. Cloudflare prints a public URL like:
   ```
   https://<random-name>.trycloudflare.com
   ```

Note: quick tunnels are temporary and the URL changes on each restart. For a permanent URL, create an account and use a named tunnel pointed at your own domain.
