# ... all your original imports remain unchanged
from fastapi import FastAPI, HTTPException, Depends, Request, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi_sqlalchemy import DBSessionMiddleware, db
from pydantic import BaseModel
from sqlalchemy.orm import sessionmaker
from urllib.parse import urlparse

# ------------------- FastAPI App Config -------------------

app = FastAPI(
    title="SuperAGI",
    docs_url="/docs",         # ✅ ensures Swagger UI is accessible
    redoc_url="/redoc",       # ✅ optional Redoc UI
    openapi_url="/openapi.json"
)

# ------------------- Middleware & DB Setup -------------------

from superagi.config.config import get_config
from superagi.models.db import connect_db

db_host = get_config('DB_HOST')
db_url = get_config('DB_URL')
db_username = get_config('DB_USERNAME')
db_password = get_config('DB_PASSWORD')
db_name = get_config('DB_NAME')
env = get_config('ENV', "DEV")

if db_url is None:
    if db_username is None:
        db_url = f'postgresql://{db_host}/{db_name}'
    else:
        db_url = f'postgresql://{db_username}:{db_password}@{db_host}/{db_name}'
else:
    db_url = urlparse(db_url)
    db_url = db_url.scheme + "://" + db_url.netloc + db_url.path

engine = connect_db()
Session = sessionmaker(bind=engine)
session = Session()

app.add_middleware(DBSessionMiddleware, db_url=db_url)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- Alembic Migrations -------------------

import subprocess
from superagi.lib.logger import logger

def run_migrations():
    try:
        logger.info("🔧 Running Alembic migrations...")
        subprocess.run(
            ["alembic", "upgrade", "head"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except subprocess.CalledProcessError as e:
        logger.error("⚠️ Alembic migration failed:")
        logger.error(e.stderr)

# ------------------- Startup Tasks -------------------

from superagi.models.organisation import Organisation
from superagi.models.user import User
from superagi.models.models_config import ModelsConfig
from superagi.models.agent_template import AgentTemplate
from superagi.models.workflows.agent_workflow import AgentWorkflow
from superagi.models.workflows.iteration_workflow import IterationWorkflow
from superagi.agent.workflow_seed import AgentWorkflowSeed, IterationWorkflowSeed
from superagi.helper.tool_helper import register_toolkits, register_marketplace_toolkits

def replace_old_iteration_workflows(session):
    templates = session.query(AgentTemplate).all()
    for template in templates:
        iter_workflow = IterationWorkflow.find_by_id(session, template.agent_workflow_id)
        if not iter_workflow:
            continue
        name_map = {
            "Fixed Task Queue": "Fixed Task Workflow",
            "Maintain Task Queue": "Dynamic Task Workflow",
            "Don't Maintain Task Queue": "Goal Based Workflow",
            "Goal Based Agent": "Goal Based Workflow",
        }
        if iter_workflow.name in name_map:
            agent_workflow = AgentWorkflow.find_by_name(session, name_map[iter_workflow.name])
            template.agent_workflow_id = agent_workflow.id
            session.commit()

@app.on_event("startup")
async def startup_event():
    logger.info("Running Startup tasks")
    Session = sessionmaker(bind=engine)
    session = Session()

    def table_exists(table_name: str) -> bool:
        try:
            return engine.dialect.has_table(engine.connect(), table_name)
        except Exception as e:
            logger.error(f"Error checking table '{table_name}': {e}")
            return False

    try:
        run_migrations()

        if table_exists("users") and table_exists("organisations"):
            default_user = session.query(User).filter(User.email == "super6@agi.com").first()
            if default_user:
                organisation = session.query(Organisation).filter_by(id=default_user.organisation_id).first()
                if organisation:
                    register_toolkits(session, organisation)

        if table_exists("agent_workflows"):
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

            allowed_workflows = [
                "Sales Engagement Workflow", "Recruitment Workflow", "SuperCoder",
                "Goal Based Workflow", "Dynamic Task Workflow", "Fixed Task Workflow"
            ]
            workflows_to_remove = session.query(AgentWorkflow).filter(
                AgentWorkflow.name.not_in(allowed_workflows)).all()
            for workflow in workflows_to_remove:
                session.delete(workflow)

            replace_old_iteration_workflows(session)

        if env != "PROD":
            if table_exists("organisations"):
                organizations = session.query(Organisation).all()
                for org in organizations:
                    register_toolkits(session, org)
        else:
            marketplace_organisation_id = get_config("MARKETPLACE_ORGANISATION_ID")
            if marketplace_organisation_id and table_exists("organisations"):
                org = session.query(Organisation).filter_by(id=marketplace_organisation_id).first()
                if org:
                    register_marketplace_toolkits(session, org)

        session.commit()

    except Exception as e:
        logger.error(f"Startup event error: {e}")
    finally:
        session.close()

# ------------------- Auth & JWT -------------------

class Settings(BaseModel):
    authjwt_secret_key: str = get_config("JWT_SECRET_KEY")

@AuthJWT.load_config
def get_config_jwt():
    return Settings()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

from superagi.models.types.login_request import LoginRequest
from superagi.models.types.validate_llm_api_key_request import ValidateAPIKeyRequest
from superagi.llms.llm_model_factory import build_model_with_api_key
from superagi.llms.openai import OpenAi

def create_access_token(email, Authorize: AuthJWT = Depends()):
    expiry = int(get_config("JWT_EXPIRY", 200))
    return Authorize.create_access_token(subject=email, expires_time=timedelta(hours=expiry))

@app.post("/login")
def login(request: LoginRequest, Authorize: AuthJWT = Depends()):
    user = db.session.query(User).filter(User.email == request.email).first()
    if user is None or request.password != user.password:
        raise HTTPException(status_code=401, detail="Bad username or password")
    return {"access_token": create_access_token(user.email, Authorize)}

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
    except:
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
    except:
        raise HTTPException(status_code=401, detail="Invalid API Key")

# ------------------- Basic Utility Routes -------------------

@app.get("/")
def root():
    return {"message": "SuperAGI backend is running!"}

@app.get("/ping")
def ping():
    return {"message": "pong"}

@app.get("/hello/{name}")
def hello(name: str, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    return {"message": f"Hello {name}"}

@app.get('/get/github_client_id')
def github_client_id():
    return {"github_client_id": get_config("GITHUB_CLIENT_ID", "").strip()}

# ------------------- Include API Routers -------------------

from superagi.controllers import (
    agent as agent_router,
    agent_execution as agent_execution_router,
    agent_execution_feed as agent_execution_feed_router,
    agent_execution_permission as agent_execution_permission_router,
    agent_template as agent_template_router,
    agent_workflow as agent_workflow_router,
    budget as budget_router,
    config as config_router,
    organisation as organisation_router,
    project as project_router,
    twitter_oauth as twitter_oauth_router,
    google_oauth as google_oauth_router,
    resources as resources_router,
    tool as tool_router,
    tool_config as tool_config_router,
    toolkit as toolkit_router,
    user as user_router,
    agent_execution_config as agent_execution_config,
    analytics as analytics_router,
    models_controller as models_controller_router,
    knowledges as knowledges_router,
    knowledge_configs as knowledge_configs_router,
    vector_dbs as vector_dbs_router,
    vector_db_indices as vector_db_indices_router,
    marketplace_stats as marketplace_stats_router,
    api_key as api_key_router,
    api as api_agent_router,
    webhook as web_hook_router
)

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
app.include_router(api_agent_router.router, prefix="/v1/agent")  # note .router for APIRouter inside module
app.include_router(web_hook_router, prefix="/webhook")
