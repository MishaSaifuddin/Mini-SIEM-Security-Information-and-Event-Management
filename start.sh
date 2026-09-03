#!/bin/bash
# Start Mini SIEM backend and frontend
echo "========================================"
echo "  Mini SIEM - Starting Services"
echo "========================================"
echo ""

# Start backend
cd "$(dirname "$0")/backend"
./venv/bin/python -m uvicorn app.main:app --reload --port 8000 &
BACKEND_PID=$!

# Start frontend
cd "$(dirname "$0")/frontend"
npm start &
FRONTEND_PID=$!

echo "Backend:  http://localhost:8000  (API docs at /docs)"
echo "Frontend: http://localhost:3000"
echo ""
echo "Default login: admin / admin123"
echo ""
echo "Press Ctrl+C to stop both services"
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" INT TERM
wait
