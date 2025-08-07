from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi_sqlalchemy import db
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

from superagi.models.organisation import Organisation
from superagi.models.project import Project
from superagi.models.user import User
from superagi.models.models_config import ModelsConfig

from superagi.helper.auth import check_auth, get_current_user
from superagi.lib.logger import logger

router = APIRouter()


# Pydantic Models
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


# Routes
@router.post("/add", response_model=UserOut, status_code=201)
def create_user(user: UserIn, Authorize: AuthJWT = Depends(check_auth)):
    """
    Create a new user.
    """
    logger.info("Received user data: %s", user)

    if not user.name or not user.email or not user.password:
        logger.error("Missing required fields.")
        raise HTTPException(status_code=422, detail="Missing required fields: name, email, or password")

    existing_user = db.session.query(User).filter(User.email == user.email).first()
    if existing_user:
        return existing_user

    org_id = user.organisation_id or 1  # Fallback default org ID
    new_user = User(name=user.name, email=user.email, password=user.password, organisation_id=org_id)

    try:
        db.session.add(new_user)
        db.session.commit()
        db.session.flush()
    except Exception as e:
        logger.error(f"Failed to create user: {str(e)}")
        db.session.rollback()
        raise HTTPException(status_code=500, detail="User creation failed")

    try:
        organisation = Organisation.find_or_create_organisation(db.session, new_user)
        Project.find_or_create_default_project(db.session, organisation.id)
        ModelsConfig.add_llm_config(db.session, organisation.id)
    except Exception as e:
        logger.warning(f"Post-user creation setup failed: {str(e)}")

    return new_user


@router.get("/get/{user_id}", response_model=UserOut)
def get_user(user_id: int, Authorize: AuthJWT = Depends(check_auth)):
    """
    Get user by ID.
    """
    db_user = db.session.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.put("/update/{user_id}", response_model=UserOut)
def update_user(user_id: int, user: UserBase, Authorize: AuthJWT = Depends(check_auth)):
    """
    Update user details.
    """
    db_user = db.session.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.name = user.name
    db_user.email = user.email
    db_user.password = user.password

    db.session.commit()
    return db_user


@router.post("/first_login_source/{source}")
def update_first_login_source(source: str, Authorize: AuthJWT = Depends(check_auth)):
    """
    Update user's first login source.
    """
    user = get_current_user(Authorize)
    if not user.first_login_source:
        user.first_login_source = source
        db.session.commit()
        db.session.flush()
    logger.info(f"First login source updated: {user}")
    return user
