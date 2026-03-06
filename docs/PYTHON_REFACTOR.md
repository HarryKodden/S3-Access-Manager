**Python Refactor Migration Notes**

Overview
- A new Python FastAPI service scaffold was added under `py_gateway/` to begin porting the Go server logic.

What was added
- `py_gateway/` - FastAPI app skeleton with `app/main.py`, `app/routers/settings.py`, `app/routers/tenants.py`, and `app/config.py`.
- `py_gateway/Dockerfile` and `py_gateway/requirements.txt`.
- `docker-compose.yml` updated with a `py_gateway` service for side-by-side testing.

How to run the Python service locally

1. Install deps and run with Uvicorn:

```bash
python -m pip install -r py_gateway/requirements.txt
uvicorn app.main:app --reload --port 9000 --app-dir py_gateway
```

2. Or with Docker (from repo root):

```bash
docker build -t s3-gateway-py ./py_gateway
docker run --rm -p 9000:9000 \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v $(pwd)/frontend:/app/frontend:ro \
  -v $(pwd)/data:/app/data \
  s3-gateway-py
```

Notes and next steps
- Current implementation ports tenant `settings` handlers (credentials, policies, roles, and sram-groups) as filesystem-backed JSON files to match the Go layout.
- Next work: wire authentication, IAM integrations, metrics, and full API parity. Consider incremental endpoint-by-endpoint porting and running integration tests.
