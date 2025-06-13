from fastapi import APIRouter, HTTPException
from starlette.concurrency import run_in_threadpool
from .ldap_utils import authenticate_user, get_user_group
from .models import LoginRequest, TokenResponse
from .token_utils import create_access_tokens

router = APIRouter()

@router.post("/login",response_model=TokenResponse)
async def login_user(login: LoginRequest):
    is_valid = await run_in_threadpool(authenticate_user, login.username, login.password)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid username and password")
    
    role = await run_in_threadpool(get_user_group, login.username)
    if not role:
        raise HTTPException(status_code=403, detail="User has no group assigned")
    
    token = create_access_tokens({"sub":login.username, "role":role})
    return TokenResponse(access_token=token)