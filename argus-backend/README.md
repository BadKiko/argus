# Argus Memory Backend

Remote vector memory for Argus RE sessions: FastAPI + Chroma + Gemini Embedding 2.

## Deploy (Docker)

```bash
cp .env.example .env
# set GEMINI_API_KEY in .env
docker compose up -d --build
curl http://127.0.0.1:8787/v1/health
```

## API

- `GET /v1/health`
- `POST /v1/cases` — ingest structured case report
- `POST /v1/search` — vector similarity search
- `GET /v1/stats`

## Volumes

- `chroma_data` — vector index (portable)
- `api_data` — optional cache

## TLS

Expose only on localhost (`127.0.0.1:8787`); put Caddy/nginx in front for `argus.cloud.badkiko.ru`.

Example Caddyfile snippet:

```text
argus.cloud.badkiko.ru {
    reverse_proxy 127.0.0.1:8787
}
```

## Tests

```bash
pip install -r requirements.txt pytest
pytest tests/
```
