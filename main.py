# main.py
import os
import subprocess
from datetime import timedelta
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi_sqlalchemy import DBSessionMiddleware, db
from pydantic import BaseModel
from sqlalchemy.orm import sessionmaker

# --- SuperAGI imports
import superagi
from superagi.config.config import get_config as sa_get_config
from superagi.lib.logger import logger
from superagi.models.db import connect_db
from superagi.models.user import User
from superagi.models.organisation import Organisation
from superagi.models.agent_template import AgentTemplate
from superagi.models.workflows.agent_workflow import AgentWorkflow
from superagi.models.workflows.iteration_workflow import IterationWorkflow
from superagi.models.types.login_request import LoginRequest
from superagi.models.types.validate_llm_api_key_request import ValidateAPIKeyRequest
from superagi.llms.llm_model_factory import build_model_with_api_key
from superagi.llms.openai import OpenAi
from superagi.agent.workflow_seed import IterationWorkflowSeed, AgentWorkflowSeed
from superagi.helper.tool_helper import register_toolkits, register_marketplace_toolkits

# --- Routers
from superagi.controllers.agent import router as agent_router
from superagi.controllers.agent_execution import router as agent_execution_router
from superagi.controllers.agent_execution_feed import router as agent_execution_feed_router
from superagi.controllers.agent_execution_permission import router as agent_execution_permission_router
from superagi.controllers.agent_template import router as agent_template_router
from superagi.controllers.agent_workflow import router as agent_workflow_router
from superagi.controllers.budget import router as budget_router
from superagi.controllers.config import router as config_router
from superagi.controllers.organisation import router as organisation_router
from superagi.controllers.project import router as project_router
from superagi.controllers.twitter_oauth import router as twitter_oauth_router
from superagi.controllers.google_oauth import router as google_oauth_router
from superagi.controllers.resources import router as resources_router
from superagi.controllers.tool import router as tool_router
from superagi.controllers.tool_config import router as tool_config_router
from superagi.controllers.toolkit import router as toolkit_router
from superagi.controllers.user import router as user_router
from superagi.controllers.agent_execution_config import router as agent_execution_config
from superagi.controllers.analytics import router as analytics_router
from superagi.controllers.models_controller import router as models_controller_router
from superagi.controllers.knowledges import router as knowledges_router
from superagi.controllers.knowledge_configs import router as knowledge_configs_router
from superagi.controllers.vector_dbs import router as vector_dbs_router
from superagi.controllers.vector_db_indices import router as vector_db_indices_router
from superagi.controllers.marketplace_stats import router as marketplace_stats_router
from superagi.controllers.api_key import router as api_key_router
from superagi.controllers.api.agent import router as api_agent_router
from superagi.controllers.webhook import router as web_hook_router

# =============================================================================
# App
# =============================================================================
app = FastAPI(
    title="SuperAGI",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Helpers to read config: prefer env, fallback to SuperAGI config
def cfg(key: str, default=None):
    return os.getenv(key) or sa_get_config(key, default)

# =============================================================================
# DB setup
# =============================================================================
def build_db_url() -> str:
    raw_url = cfg("DB_URL")
    if raw_url:
        # Normalize possible DSN into SQLAlchemy format
        parsed = urlparse(raw_url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    host = cfg("DB_HOST")
    user = cfg("DB_USERNAME")
    pwd = cfg("DB_PASSWORD")
    name = cfg("DB_NAME")

    # Fallbacks for Railway typical env (only if not provided)
    if not host:
        host = "postgres.railway.internal"
    if not name:
        name = "railway"

    if user and pwd:
        return f"postgresql://{user}:{pwd}@{host}/{name}"
    else:
        # passwordless/local
        return f"postgresql://{host}/{name}"

db_url = build_db_url()
engine = connect_db()  # uses SuperAGI's internal logic (already adjusted in your repo)
SessionLocal = sessionmaker(bind=engine)

# FastAPI-SQLAlchemy middleware needs a URL string
app.add_middleware(DBSessionMiddleware, db_url=db_url)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# JWT / Auth
# =============================================================================
JWT_SECRET = cfg("JWT_SECRET_KEY")
if not JWT_SECRET:
    logger.error("❌ JWT_SECRET_KEY not found in environment or config.")
else:
    logger.info("✅ JWT_SECRET_KEY detected from environment/config.")

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

# =============================================================================
# Migrations
# =============================================================================
def run_migrations():
    try:
        logger.info("🔧 Running Alembic migrations...")
        subprocess.run(
            ["alembic", "upgrade", "head"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error("⚠️ Alembic migration failed:")
        logger.error(e.stderr)

# =============================================================================
# Startup tasks
# =============================================================================
def replace_old_iteration_workflows(session):
    templates = session.query(AgentTemplate).all()
    name_map = {
        "Fixed Task Queue": "Fixed Task Workflow",
        "Maintain Task Queue": "Dynamic Task Workflow",
        "Don't Maintain Task Queue": "Goal Based Workflow",
        "Goal Based Agent": "Goal Based Workflow",
    }
    for template in templates:
        iter_flow = IterationWorkflow.find_by_id(session, template.agent_workflow_id)
        if not iter_flow:
            continue
        if iter_flow.name in name_map:
            wf = AgentWorkflow.find_by_name(session, name_map[iter_flow.name])
            if wf:
                template.agent_workflow_id = wf.id
                session.commit()

@app.on_event("startup")
async def startup_event():
    logger.info("Running Startup tasks")
    run_migrations()

    session = SessionLocal()
    try:
        # Seed workflows (guarded by tables existing inside these helpers)
        IterationWorkflowSeed.build_single_step_agent(session)
        IterationWorkflowSeed.build_task_based_agents(session)
        IterationWorkflowSeed.build_action_based_agents(session)
        IterationWorkflowSeed.build_initialize_task_workflow(session)

        AgentWorkflowSeed.build_goal_based_agent(session)
        AgentWorkflowSeed.build_task_based_agent(session)
        AgentWorkflowSeed.build_fixed_task_based_agent(session)
        AgentWorkflowSeed.build_sales_workflow(session)
        AgentWorkflowSeed.build_recruitment_workflow(session)
        AgentWorkflowSeed.build_coding_workflow(session)

        # Clean up old workflow names
        allowed = [
            "Sales Engagement Workflow",
            "Recruitment Workflow",
            "SuperCoder",
            "Goal Based Workflow",
            "Dynamic Task Workflow",
            "Fixed Task Workflow",
        ]
        for wf in session.query(AgentWorkflow).filter(AgentWorkflow.name.not_in(allowed)).all():
            session.delete(wf)

        replace_old_iteration_workflows(session)

        # Register toolkits
        env = cfg("ENV", "DEV")
        if env != "PROD":
            for org in session.query(Organisation).all():
                register_toolkits(session, org)
            logger.info("Successfully registered local toolkits for all Organisations!")
        else:
            marketplace_org_id = cfg("MARKETPLACE_ORGANISATION_ID")
            if marketplace_org_id:
                marketplace_org = session.query(Organisation).filter(
                    Organisation.id == marketplace_org_id
                ).first()
                if marketplace_org:
                    register_marketplace_toolkits(session, marketplace_org)

        session.commit()
    except Exception as e:
        logger.error(f"Startup event error: {e}")
    finally:
        session.close()

# =============================================================================
# Routes
# =============================================================================

@app.get("/")
def root():
    return {"message": "SuperAGI backend is running!"}

@app.get("/ping")
def ping():
    return {"message": "pong"}

@app.post("/login")
def login(request: LoginRequest, Authorize: AuthJWT = Depends()):
    logger.info(f"🔐 /login called for email='{request.email}'")
    if not JWT_SECRET:
        # Hard fail if secret is missing
        raise HTTPException(status_code=500, detail="Server JWT misconfiguration. Set JWT_SECRET_KEY and redeploy.")
    user = db.session.query(User).filter(User.email == request.email).first()
    if user is None or request.password != user.password:
        raise HTTPException(status_code=401, detail="Bad username or password")
    token = create_access_token(user.email, Authorize)
    return {"access_token": token}

@app.get("/user")
def get_user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    return {"user": Authorize.get_jwt_subject()}

@app.get("/validate-access-token")
def validate_token(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        user_email = Authorize.get_jwt_subject()
        return db.session.query(User).filter(User.email == user_email).first()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/validate-llm-api-key")
def validate_llm_api_key(request: ValidateAPIKeyRequest):
    model = build_model_with_api_key(request.model_source, request.model_api_key)
    if model and model.verify_access_key():
        return {"message": "Valid API Key", "status": "success"}
    return {"message": "Invalid API Key", "status": "failed"}

@app.get("/validate-open-ai-key/{open_ai_key}")
def validate_openai(open_ai_key: str):
    try:
        OpenAi(api_key=open_ai_key).chat_completion([{"role": "system", "content": "Hey!"}])
        return {"message": "Valid key"}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid API Key")

@app.get('/get/github_client_id')
def github_client_id():
    return {"github_client_id": (cfg("GITHUB_CLIENT_ID", "") or "").strip()}

# =============================================================================
# Include Routers
# =============================================================================
app.include_router(user_router, prefix="/users")
app.include_router(tool_router, prefix="/tools")
app.include_router(organisation_router, prefix="/organisations")
app.include_router(project_router, prefix="/projects")
app.include_router(budget_router, prefix="/budgets")
app.include_router(agent_router, prefix="/agents")
app.include_router(agent_execution_router, prefix="/agentexecutions")
app.include_router(agent_execution_feed_router, prefix="/agentexecutionfeeds")
app.include_router(agent_execution_permission_router, prefix="/agentexecutionpermissions")
app.include_router(resources_router, prefix="/resources")
app.include_router(config_router, prefix="/configs")
app.include_router(toolkit_router, prefix="/toolkits")
app.include_router(tool_config_router, prefix="/tool_configs")
app.include_router(agent_template_router, prefix="/agent_templates")
app.include_router(agent_workflow_router, prefix="/agent_workflows")
app.include_router(twitter_oauth_router, prefix="/twitter")
app.include_router(agent_execution_config, prefix="/agent_executions_configs")
app.include_router(analytics_router, prefix="/analytics")
app.include_router(models_controller_router, prefix="/models_controller")
app.include_router(google_oauth_router, prefix="/google")
app.include_router(knowledges_router, prefix="/knowledges")
app.include_router(knowledge_configs_router, prefix="/knowledge_configs")
app.include_router(vector_dbs_router, prefix="/vector_dbs")
app.include_router(vector_db_indices_router, prefix="/vector_db_indices")
app.include_router(marketplace_stats_router, prefix="/marketplace")
app.include_router(api_key_router, prefix="/api-keys")
app.include_router(api_agent_router, prefix="/v1/agent")
app.include_router(web_hook_router, prefix="/webhook")
