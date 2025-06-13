from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from starlette.concurrency import run_in_threadpool
from .ldap_utils import authenticate_user, get_user_group
from .models import LoginRequest, TokenResponse
from .token_utils import create_access_tokens

router = APIRouter()

@router.post("/login",response_model=TokenResponse)
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    is_valid = await run_in_threadpool(authenticate_user, username, password)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid username and password")
    
    role = await run_in_threadpool(get_user_group, username)
    if not role:
        raise HTTPException(status_code=403, detail="User has no group assigned")
    
    token = create_access_tokens({"sub":username, "role":role})
    return TokenResponse(access_token=token)