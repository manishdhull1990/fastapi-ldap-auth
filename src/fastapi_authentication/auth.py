from fastapi import APIRouter, HTTPException, Depends,Request
from fastapi.security import OAuth2PasswordRequestForm
from starlette.concurrency import run_in_threadpool
from .ldap_utils import authenticate_user, get_user_group
from .models import LoginRequest, TokenResponse, RefreshRequest
from .token_utils import create_access_tokens, decode_token, log_token

from datetime import datetime, timedelta

router = APIRouter()

@router.post("/login",response_model=TokenResponse)
async def login_user(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    is_valid = await run_in_threadpool(authenticate_user, username, password)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid username and password")
    
    role = await run_in_threadpool(get_user_group, username)
    if not role:
        raise HTTPException(status_code=403, detail="User has no group assigned")
    
    access_token, refresh_token, access_expires, refresh_expires = create_access_tokens({"sub":username, "role":role})

    log_token(username, role, access_token, refresh_token, access_expires, refresh_expires, request)
    # Log the token
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(payload: RefreshRequest, request: Request):
    decoded = decode_token(payload.refresh_token)
    username = decoded.get("sub")

    if not username:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    role = await run_in_threadpool(get_user_group, username)
    if not role:
         raise HTTPException(status_code=403, detail="User has no group assigned")
    
    access_token, new_refresh_token, access_expires, refresh_expires  = create_access_tokens({"sub":username, "role": role})
    log_token(username, role, access_token, new_refresh_token, access_expires, refresh_expires, request)

    return TokenResponse(access_token=access_token, refresh_token= new_refresh_token)