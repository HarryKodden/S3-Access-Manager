from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from app.config import load_config
from app.routers import tenants, settings
from app.auth import OIDCMiddleware, require_auth

app = FastAPI(title="S3 Access Manager (Python)")

# Load config once at startup
CONFIG = load_config("config.yaml")

# CORS setup (basic)
origins = CONFIG.get("logging", {}).get("cors_origins") or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attach lightweight OIDC middleware (calls /userinfo when bearer token present)
app.add_middleware(OIDCMiddleware)


@app.get("/health")
def health():
    # Minimal health placeholder
    return {"status": "healthy", "version": "0.0.0-py"}


# Serve frontend static files (mirrors Go behavior)
@app.get("/app.js")
def app_js():
    return FileResponse("./frontend/app.js")


@app.get("/styles.css")
def styles():
    return FileResponse("./frontend/styles.css")


# Serve index and SPA fallback
@app.get("/")
def index():
    return FileResponse("./frontend/index.html")


@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    # If requested file exists under frontend, serve it; otherwise return index.html
    from pathlib import Path

    fp = Path("./frontend") / full_path
    if fp.exists() and fp.is_file():
        return FileResponse(str(fp))
    return FileResponse("./frontend/index.html")


app.include_router(tenants.router, dependencies=[Depends(require_auth)])
app.include_router(settings.router, dependencies=[Depends(require_auth)])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=9000, reload=True)
