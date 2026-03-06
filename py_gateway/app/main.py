import logging
import os
import threading
import time
import yaml
from contextlib import asynccontextmanager
from pathlib import Path as FSPath
from typing import Dict, Optional

from fastapi import Depends, FastAPI, Request
from fastapi import Response as FastAPIResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth import OIDCMiddleware, require_auth
from app.config import load_config
from app.routers import oidc as oidc_router
from app.routers import s3 as s3_router
from app.routers import settings, tenants

logger = logging.getLogger(__name__)

# Load config once at module import time.
CONFIG = load_config("config.yaml")

# ---------------------------------------------------------------------------
# Background services: SCIM→IAM sync + filesystem watcher
# ---------------------------------------------------------------------------

# Lazy imports so missing optional deps only fail at startup, not import time.
try:
    from app.backend import AWSAdmin
    from app.sync_service import SyncService
    from app.watcher import FileWatcher
    _BACKGROUND_AVAILABLE = True
except ImportError as _bg_err:
    logger.warning("Background services unavailable: %s", _bg_err)
    _BACKGROUND_AVAILABLE = False

_sync_services: Dict[str, "SyncService"] = {}
_file_watcher: Optional["FileWatcher"] = None


def _discover_tenants(data_dir: str = "./data/tenants"):
    """Yield per-tenant config dicts auto-discovered from *data_dir*."""
    d = FSPath(data_dir)
    if not d.exists():
        return
    for entry in sorted(d.iterdir()):
        if not entry.is_dir():
            continue
        cfg_file = entry / "config.yaml"
        if not cfg_file.exists():
            continue
        try:
            cfg = yaml.safe_load(cfg_file.read_text()) or {}
            cfg["name"] = entry.name
            cfg.setdefault("data_dir", str(entry))
            yield cfg
        except Exception as exc:
            logger.warning("Failed to load tenant config %s: %s", cfg_file, exc)


def _init_sync_services(global_cfg: dict) -> Dict[str, "SyncService"]:
    """Return a SyncService per discovered tenant."""
    if not _BACKGROUND_AVAILABLE:
        return {}
    s3_cfg = global_cfg.get("s3") or {}
    services: Dict[str, SyncService] = {}
    for tenant in _discover_tenants():
        name = tenant.get("name", "")
        iam = tenant.get("iam") or {}
        data_dir = tenant.get("data_dir") or f"./data/tenants/{name}"

        admin = None
        if iam.get("access_key") and iam.get("secret_key"):
            try:
                admin = AWSAdmin(
                    access_key=iam["access_key"],
                    secret_key=iam["secret_key"],
                    region=s3_cfg.get("region"),
                    endpoint=s3_cfg.get("endpoint"),
                )
            except Exception as exc:
                logger.warning("Failed to init IAM client for tenant %s: %s", name, exc)

        policies_dir = (
            (tenant.get("policies") or {}).get("directory")
            or f"{data_dir}/policies"
        )
        roles_dir = (
            (tenant.get("roles") or {}).get("directory")
            or f"{data_dir}/roles"
        )
        credentials_file = (
            (tenant.get("credentials") or {}).get("file")
            or f"{data_dir}/credentials.json"
        )
        tenant_admins = tenant.get("tenant_admins") or []
        admin_username = tenant_admins[0] if tenant_admins else ""

        services[name] = SyncService(
            admin=admin,
            policies_dir=policies_dir,
            roles_dir=roles_dir,
            credentials_file=credentials_file,
            admin_username=admin_username,
        )
        logger.info("Initialized sync service for tenant %s", name)
    return services


def _run_initial_sync(services: Dict[str, "SyncService"]) -> None:
    for tenant_name, svc in services.items():
        try:
            logger.info("Running initial SCIM sync for tenant %s", tenant_name)
            svc.sync_all_scim()
        except Exception as exc:
            logger.error("Initial sync failed for tenant %s: %s", tenant_name, exc)


@asynccontextmanager
async def lifespan(app_: FastAPI):
    """FastAPI lifespan: start background sync + file watcher on startup."""
    global _sync_services, _file_watcher

    _sync_services = _init_sync_services(CONFIG)

    if _sync_services and _BACKGROUND_AVAILABLE:
        # Run initial sync in a background daemon thread so startup is non-blocking.
        threading.Thread(
            target=_run_initial_sync,
            args=(_sync_services,),
            daemon=True,
            name="initial-scim-sync",
        ).start()

        # Build a single FileWatcher covering all SCIM dirs + per-tenant policy dirs.
        def _on_fs_change():
            for tname, svc in _sync_services.items():
                try:
                    svc.sync_all_scim()
                except Exception as exc:
                    logger.error("File-triggered sync failed for tenant %s: %s", tname, exc)

        _file_watcher = FileWatcher(sync_callback=_on_fs_change)

        # Global SCIM directories.
        for scim_dir in ["./data/scim/Users", "./data/scim/Groups"]:
            FSPath(scim_dir).mkdir(parents=True, exist_ok=True)
            try:
                _file_watcher.add_directory(scim_dir)
            except Exception as exc:
                logger.warning("Cannot watch %s: %s", scim_dir, exc)

        # Per-tenant policy directories.
        for tenant_cfg in _discover_tenants():
            tname = tenant_cfg.get("name", "")
            tdata = tenant_cfg.get("data_dir") or f"./data/tenants/{tname}"
            pol_dir = (
                (tenant_cfg.get("policies") or {}).get("directory")
                or f"{tdata}/policies"
            )
            FSPath(pol_dir).mkdir(parents=True, exist_ok=True)
            try:
                _file_watcher.add_directory(pol_dir)
            except Exception as exc:
                logger.warning("Cannot watch %s: %s", pol_dir, exc)

        _file_watcher.start()

    yield

    # --- shutdown ---
    if _file_watcher is not None:
        _file_watcher.close()

# ---------------------------------------------------------------------------
# Prometheus metrics (mirrors Go middleware/metrics.go)
# ---------------------------------------------------------------------------
_requests_total = Counter(
    "s3_gateway_requests_total",
    "Total number of HTTP requests",
    ["method", "path", "status"],
)
_request_duration = Histogram(
    "s3_gateway_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
)


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        path = request.url.path
        _requests_total.labels(request.method, path, str(response.status_code)).inc()
        _request_duration.labels(request.method, path).observe(duration)
        return response


# ---------------------------------------------------------------------------
# Security headers (mirrors Go middleware/security.go)
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
        return response


# ---------------------------------------------------------------------------
# Rate limiting (mirrors Go middleware/ratelimit.go – token bucket per IP)
# ---------------------------------------------------------------------------
class _TokenBucket:
    def __init__(self, rate: float, burst: int):
        self._rate = rate  # tokens added per second
        self._burst = float(burst)
        self._tokens: dict[str, float] = {}
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()
        # cleanup stale entries every 5 minutes
        self._start_cleanup()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(ip, now)
            tokens = self._tokens.get(ip, self._burst)
            # refill
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            self._last[ip] = now
            if tokens >= 1.0:
                self._tokens[ip] = tokens - 1.0
                return True
            self._tokens[ip] = tokens
            return False

    def _cleanup(self):
        now = time.monotonic()
        with self._lock:
            stale = [ip for ip, last in self._last.items() if now - last > 300]
            for ip in stale:
                self._last.pop(ip, None)
                self._tokens.pop(ip, None)
        t = threading.Timer(300, self._cleanup)
        t.daemon = True
        t.start()

    def _start_cleanup(self):
        t = threading.Timer(300, self._cleanup)
        t.daemon = True
        t.start()


_rate_limiter = _TokenBucket(rate=100.0, burst=200)  # 100 req/s, burst 200


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        if not _rate_limiter.allow(ip):
            return FastAPIResponse(
                content='{"error":"Rate limit exceeded. Please try again later."}',
                status_code=429,
                media_type="application/json",
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# FastAPI application (lifespan wires sync + watcher startup/shutdown)
# ---------------------------------------------------------------------------
app = FastAPI(title="S3 Access Manager (Python)", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Register middleware (order: outermost first in add_middleware)
# ---------------------------------------------------------------------------

# Attach lightweight OIDC middleware (calls /userinfo when bearer token present)
app.add_middleware(OIDCMiddleware)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(PrometheusMiddleware)

# CORS setup (basic)
origins = CONFIG.get("logging", {}).get("cors_origins") or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# API routers – registered BEFORE the SPA wildcard so they are matched first
# ---------------------------------------------------------------------------
app.include_router(tenants.router, dependencies=[Depends(require_auth)])
app.include_router(settings.router, dependencies=[Depends(require_auth)])
app.include_router(oidc_router.router)
app.include_router(s3_router.router, dependencies=[Depends(require_auth)])


# ---------------------------------------------------------------------------
# Core API endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "healthy", "version": "0.0.0-py"}


@app.get("/metrics")
def metrics():
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


# ---------------------------------------------------------------------------
# Static frontend files
# ---------------------------------------------------------------------------

@app.get("/app.js")
def app_js():
    return FileResponse("./frontend/app.js")


@app.get("/styles.css")
def styles():
    return FileResponse("./frontend/styles.css")


def _serve_index_with_bypass() -> Response:
    """Return index.html, injecting bypass localStorage script when enabled."""
    if os.getenv("OIDC_BYPASS", "false").lower() in ("1", "true", "yes"):
        try:
            idx = open("./frontend/index.html", "r", encoding="utf-8").read()
            bypass_email = os.getenv("BYPASS_EMAIL", "harry@kodden.nl")
            bypass_groups = [g.strip() for g in (os.getenv("BYPASS_GROUPS", "test-group") or "").split(",") if g.strip()]
            script = f"""
<script>
try {{
  localStorage.setItem('auth_token', 'bypass-token');
  localStorage.setItem('user_info', JSON.stringify({{'email':'{bypass_email}','name':'{bypass_email}','sub':'{bypass_email}','groups':{bypass_groups}}}));
  localStorage.setItem('is_admin', 'false');
  localStorage.setItem('is_global_admin', 'false');
}} catch(e) {{ console.error('bypass localStorage injection failed', e); }}
</script>
"""
            return Response(content=idx.replace('<body>', '<body>' + script, 1), media_type="text/html")
        except Exception:
            pass
    return FileResponse("./frontend/index.html")


@app.get("/")
def index():
    return _serve_index_with_bypass()


# SPA catch-all – MUST be last so API routes above take priority
@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    from pathlib import Path as _Path
    fp = _Path("./frontend") / full_path
    if fp.exists() and fp.is_file():
        return FileResponse(str(fp))
    return _serve_index_with_bypass()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=9000, reload=True)
