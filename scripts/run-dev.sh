#!/usr/bin/env bash
# Start the application in Development mode (Fake directory, development sign-in).
set -euo pipefail
cd "$(dirname "$0")/.."
export SD_ENVIRONMENT=Development
exec python -m uvicorn app.main:app_factory --factory --port "${PORT:-8000}" --reload
