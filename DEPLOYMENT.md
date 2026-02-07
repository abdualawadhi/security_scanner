# Deployment Guide

This guide describes deployment options for the Website Security Scanner.

## Environment Variables
See `.env.example` for required and optional configuration. The web UI requires
`SECRET_KEY` to be set.

## Docker (Recommended)
```bash
cp .env.example .env
docker-compose up -d
```

Open `http://localhost:5000`.

## Dockerfile (Manual)
```bash
docker build -t website-security-scanner .
docker run --rm -p 5000:5000 --env-file .env website-security-scanner
```

## Local Deployment
```bash
pip install -r requirements.txt
pip install -e .
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
wss-web
```

## Production Notes
- Use HTTPS and a reverse proxy (e.g., Nginx).
- Persist `/app/data` (reports, uploads, scans) with a volume.
- Rotate `SECRET_KEY` if the environment changes.
