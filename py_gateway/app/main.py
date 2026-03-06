from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from app.config import load_config
from app.routers import tenants, settings

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


app.include_router(tenants.router)
app.include_router(settings.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=9000, reload=True)
