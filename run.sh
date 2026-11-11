#!/usr/bin/env bash
# Start KAVACH. Usage: ./run.sh            (http://localhost:8000)
#                      ./run.sh --tls      (https with a self-signed certificate)
set -e
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt
if [ "$1" = "--tls" ]; then
  python3 -m app.tls
  exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile data/tls/key.pem --ssl-certfile data/tls/cert.pem
fi
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
