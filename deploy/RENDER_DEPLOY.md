# Deploy to Render (permanent public URL)

This project deploys to [Render](https://render.com) with a **permanent URL** and a
free PostgreSQL database. Unlike the temporary Cloudflare Quick Tunnel, the Render
URL never changes.

## Files
- `render.yaml` - Render Blueprint: web service (native Python runtime) + PostgreSQL database
- `requirements.txt` (root) - references `backend/requirements.txt`
- `backend/requirements.txt` - Python deps (pinned)
- `Dockerfile` - optional local Docker build (Render uses native runtime, not this)

## Render free tier notes
- Free web service **sleeps after 15 min idle**; first request after idle takes a few
  seconds to wake. You can (optionally) set up a [UptimeRobot](https://uptimerobot.com)
  ping to http://<your-url>/api/health every 5 min to keep it awake.
- Production data lives in the managed PostgreSQL database (ephemeral disk is only
  used for the app image - do NOT rely on SQLite in production).

## Dockerfile (NOT used by Render)
Kept for local Docker builds / other hosts. Render's free tier uses the native
Python runtime defined in `render.yaml` (Docker services on Render require a paid
plan, and the Blueprint free tier needs a card on file).

The native runtime:
1. `buildCommand`: `pip install -r backend/requirements.txt` (the React app is pre-built
   locally and committed to `frontend/build/`, so Render does NOT need Node/npm)
2. `startCommand`: `uvicorn app.main:app --host 0.0.0.0 --port $PORT` from `backend/`

## Rebuilding the React frontend (when you change UI code)
From repo root:
```
cd frontend && npm run build
git add frontend/build && git commit -m "rebuild frontend" && git push
```

## Steps (deploy once)
1. Ensure the Dockerfile + render.yaml are committed and pushed to `main`.
2. Go to https://dashboard.render.com and sign up / log in (GitHub is easiest).
3. Click **New > Blueprint** and select this repo (`Mini-SIEM-Security-Information-and-Event-Management`).
4. Render reads `render.yaml`, creates the `mini-siem-db` PostgreSQL database and the
   `mini-siem` web service, and builds the Docker image.
5. Once the deploy finishes, open **https://mini-siem.onrender.com/** (or the URL
   shown in the dashboard). Login: `admin` / `admin123`.
6. Set a real `SECRET_KEY` in the service env vars for production.

## Logs / errors
- View live logs: Render dashboard > your service > Logs.
- Health check: https://<your-url>/api/health should return 200.