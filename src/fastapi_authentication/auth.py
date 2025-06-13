from fastapi import APIRouter, HTTPException
from starlette.concurrency import run_in_threadpool
from .ldap_utils import authenticate_user, get_user_group
from .models import LoginRequest, LoginResponse

router = APIRouter()

@router.post("/login",response_model=LoginResponse)
async def login_user(login: LoginRequest):
    is_valid = await run_in_threadpool(authenticate_user, login.username, login.password)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid username and password")
    
    role = await run_in_threadpool(get_user_group, login.username)
    if not role:
        raise HTTPException(status_code=403, detail="User has no group assigned")
    
    return LoginResponse(
        message="Login Successful",
        username=login.username,
        role=role
    )