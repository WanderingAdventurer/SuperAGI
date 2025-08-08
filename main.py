# main.py (diagnostic-safe)
import os
import subprocess
from datetime import timedelta
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi_sqlalchemy import DBSessionMiddleware, db
from pydantic import BaseModel
from sqlalchemy.orm import sessionmaker

# ── SuperAGI bits that are safe to import early
from superagi.config.config import get_config as sa_get_config
from superagi.lib.logger import logger
from superagi.models.db import connect_db
from superagi.models.user import User

# -----------------------------------------------------------------------------
# Helpers (prefer env var, fallback to SuperAGI config)
# -----------------------------------------------------------------------------
def cfg(key: str, default=None):
    return os.getenv(key) or sa_get_config(key, default)

def build_db_url() -> str:
    raw_url = cfg("DB_URL")
    if raw_url:
        parsed = urlparse(raw_url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    host = cfg("DB_HOST") or "postgres.railway.internal"
    user = cfg("DB_USERNAME")
    pwd  = cfg("DB_PASSWORD")
    name = cfg("DB_NAME") or "railway"

    if user and pwd:
        return f"postgresql://{user}:{pwd}@{host}/{name}"
    return f"postgresql://{host}/{name}"

DB_URL = build_db_url()

# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------
app = FastAPI(
    title="SuperAGI",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# DB middleware (string URL required)
app.add_middleware(DBSessionMiddleware, db_url=DB_URL)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# JWT config (don’t crash if missing, just block /login)
# -----------------------------------------------------------------------------
JWT_SECRET = cfg("JWT_SECRET_KEY", "").strip()
if JWT_SECRET:
    logger.info("✅ JWT_SECRET_KEY detected.")
else:
    logger.error("❌ JWT_SECRET_KEY missing. /login will fail until you set it.")

class Settings(BaseModel):
    authjwt_secret_key: str = JWT_SECRET or "MISSING"

@AuthJWT.load_config
def get_auth_settings():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

def create_access_token(email: str, Authorize: AuthJWT) -> str:
    expiry_hours = int(cfg("JWT_EXPIRY", 200))
    return Authorize.create_access_token(subject=email, expires_time=timedelta(hours=expiry_hours))

# -----------------------------------------------------------------------------
# DB engine + migrations
# -----------------------------------------------------------------------------
try:
    engine = connect_db()  # your adjusted connect_db()
    SessionLocal = sessionmaker(bind=engine)
except Exception as e:
    logger.error(f"❌ Failed to connect DB engine: {e}")
    engine = None
    SessionLocal = None

def run_migrations():
    try:
        logger.info("🔧 Running Alembic migrations...")
        subprocess.run(["alembic", "upgrade", "head"], check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logger.error("⚠️ Alembic migration failed:")
        logger.error(e.stderr or e.stdout)

# -----------------------------------------------------------------------------
# Minimal safe routes so Swagger opens even if routers fail
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "SuperAGI backend is running!"}

@app.get("/ping")
def ping():
    return {"message": "pong"}

@app.post("/login")
def login(request: "LoginRequest", Authorize: AuthJWT = Depends()):
    # lazy import pydantic model to avoid import graph issues if any
    from superagi.models.types.login_request import LoginRequest as _LR
    if not isinstance(request, _LR):
        # when called from Swagger, FastAPI will coerce into the right model
        pass

    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="Server JWT misconfiguration. Set JWT_SECRET_KEY and redeploy.")

    user = db.session.query(User).filter(User.email == request.email).first()
    if user is None or request.password != user.password:
        raise HTTPException(status_code=401, detail="Bad username or password")
    token = create_access_token(user.email, Authorize)
    return {"access_token": token}

@app.get("/validate-access-token")
def validate_token(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        user_email = Authorize.get_jwt_subject()
        return db.session.query(User).filter(User.email == user_email).first()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# -----------------------------------------------------------------------------
# Startup
# -----------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    logger.info("Running Startup tasks")
    run_migrations()
    logger.info("Startup tasks complete.")

# -----------------------------------------------------------------------------
# Try to include each router individually and log failures instead of crashing
# -----------------------------------------------------------------------------
def safe_include(import_path: str, prefix: str):
    try:
        module = __import__(import_path, fromlist=["router"])
        router = getattr(module, "router", None)
        if router is None:
            logger.error(f"❌ {import_path} has no 'router' attribute.")
            return
        app.include_router(router, prefix=prefix)
        logger.info(f"✅ Included router {import_path} at prefix '{prefix}'")
    except Exception as e:
        logger.error(f"❌ Failed to include router {import_path}: {e}")

# List of routers to include
ROUTERS = [
    ("superagi.controllers.user", "/users"),
    ("superagi.controllers.tool", "/tools"),
    ("superagi.controllers.organisation", "/organisations"),
    ("superagi.controllers.project", "/projects"),
    ("superagi.controllers.budget", "/budgets"),
    ("superagi.controllers.agent", "/agents"),
    ("superagi.controllers.agent_execution", "/agentexecutions"),
    ("superagi.controllers.agent_execution_feed", "/agentexecutionfeeds"),
    ("superagi.controllers.agent_execution_permission", "/agentexecutionpermissions"),
    ("superagi.controllers.resources", "/resources"),
    ("superagi.controllers.config", "/configs"),
    ("superagi.controllers.toolkit", "/toolkits"),
    ("superagi.controllers.tool_config", "/tool_configs"),
    ("superagi.controllers.agent_template", "/agent_templates"),
    ("superagi.controllers.agent_workflow", "/agent_workflows"),
    ("superagi.controllers.twitter_oauth", "/twitter"),
    ("superagi.controllers.agent_execution_config", "/agent_executions_configs"),
    ("superagi.controllers.analytics", "/analytics"),
    ("superagi.controllers.models_controller", "/models_controller"),
    ("superagi.controllers.google_oauth", "/google"),
    ("superagi.controllers.knowledges", "/knowledges"),
    ("superagi.controllers.knowledge_configs", "/knowledge_configs"),
    ("superagi.controllers.vector_dbs", "/vector_dbs"),
    ("superagi.controllers.vector_db_indices", "/vector_db_indices"),
    ("superagi.controllers.marketplace_stats", "/marketplace"),
    ("superagi.controllers.api_key", "/api-keys"),
    ("superagi.controllers.api.agent", "/v1/agent"),
    ("superagi.controllers.webhook", "/webhook"),
]

for mod, pref in ROUTERS:
    safe_include(mod, pref)
