# py_gateway

Minimal FastAPI scaffold for the S3 Gateway refactor. Contains basic routes and placeholders to implement parity with the Go server.

Run locally:

```bash
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 9000
```

Docker:

```bash
docker build -t s3-gateway-py ./py_gateway
docker run --rm -p 9000:9000 s3-gateway-py
```
