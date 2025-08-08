from datetime import datetime
from typing import Optional

from fastapi import HTTPException, Depends, APIRouter, Header
from pydantic import BaseModel

from superagi.models.organisation import Organisation
from superagi.models.project import Project
from superagi.models.user import User
from superagi.models.models_config import ModelsConfig
from fastapi_sqlalchemy import db  # ✅ correct import for session
from superagi.helper.auth import get_current_user
from superagi.lib.logger import logger

router = APIRouter()

# ========= AUTH HELPER =========
API_KEY_NAME = "X-API-Key"
EXPECTED_API_KEY = "superagi"  # Change if you want

def verify_api_key(x_api_key: str = Header(...)):
    logger.info(f"🔑 Expected API Key for {API_KEY_NAME} header: '{EXPECTED_API_KEY}'")
    if x_api_key != EXPECTED_API_KEY:
        logger.warning("❌ Invalid API Key provided.")
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    return True

# ========= SCHEMAS =========
class UserBase(BaseModel):
    name: str
    email: str
    password: str

    class Config:
        orm_mode = True

class UserOut(UserBase):
    id: int
    organisation_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class UserIn(UserBase):
    organisation_id: Optional[int]

    class Config:
        orm_mode = True

# ========= ROUTES =========
@router.post("/add", response_model=UserOut, status_code=201, dependencies=[Depends(verify_api_key)])
def create_user(user: UserIn):
    logger.info(f"📥 Received user data: {user}")

    # Validate input
    if not user.name or not user.email or not user.password:
        logger.error("❌ Missing required fields: name, email, or password")
        raise HTTPException(status_code=422, detail="Missing required fields: name, email, or password")

    db_user = db.session.query(User).filter(User.email == user.email).first()
    if db_user:
        logger.warning("⚠️ User already exists, returning existing user.")
        return db_user

    db_user = User(
        name=user.name,
        email=user.email,
        password=user.password,
        organisation_id=user.organisation_id
    )
    db.session.add(db_user)
    db.session.commit()
    db.session.refresh(db_user)

    organisation = Organisation.find_or_create_organisation(db.session, db_user)
    Project.find_or_create_default_project(db.session, organisation.id)
    logger.info(f"✅ User created: {db_user}")

    # Add default model config
    ModelsConfig.add_llm_config(db.session, organisation.id)

    return db_user

@router.get("/get/{user_id}", response_model=UserOut, dependencies=[Depends(verify_api_key)])
def get_user(user_id: int):
    db_user = db.session.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.put("/update/{user_id}", response_model=UserOut, dependencies=[Depends(verify_api_key)])
def update_user(user_id: int, user: UserBase):
    db_user = db.session.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.name = user.name
    db_user.email = user.email
    db_user.password = user.password

    db.session.commit()
    return db_user

@router.post("/first_login_source/{source}", dependencies=[Depends(verify_api_key)])
def update_first_login_source(source: str):
    user = get_current_user()
    if user.first_login_source is None or user.first_login_source == '':
        user.first_login_source = source
    db.session.commit()
    logger.info(f"🔄 Updated first login source for user {user.id} to {source}")
    return user
