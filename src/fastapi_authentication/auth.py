from fastapi import APIRouter, HTTPException, Depends,Request
from fastapi.security import OAuth2PasswordRequestForm
from starlette.concurrency import run_in_threadpool
from .ldap_utils import authenticate_user, get_user_group
from .models import LoginRequest, TokenResponse, RefreshRequest
from .token_utils import create_access_tokens, decode_token, log_token
from .redis_client import redis_client

import json
# from sqlalchemy.orm import Session
# from .database import SessionLocal
# from .models_database.token_log import UserToken

from datetime import datetime, timezone

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

    await log_token(username, role, access_token, refresh_token, access_expires, refresh_expires, request)
    # Log the token
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)

# @router.post("/refresh", response_model=TokenResponse)
# async def refresh_token(payload: RefreshRequest, request: Request):
#     try:
#         decoded = decode_token(payload.refresh_token)
#         username = decoded.get("sub")
#     except:
#         raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
#     if not username:
#         raise HTTPException(status_code=401, detail="Missing subject in refresh token")
    
#     # Check if the token is revoked in DB
#     with SessionLocal() as db:
#         token_record: UserToken = db.query(UserToken).filter_by(refresh_token=payload.refresh_token).first()

#         if not token_record:
#             raise HTTPException(status_code=404, detail="Refresh token not found")

#         # Step 3: Reject if revoked or expired (based on DB)
#         if token_record.is_revoked:
#             raise HTTPException(status_code=401, detail="Refresh token has already been used")

#         # Check expiration (both timestamps are timezone-aware now)
#         now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
#         expires_at_naive = token_record.refresh_expires_at.replace(tzinfo=None)
#         if now_naive>expires_at_naive:
#             raise HTTPException(status_code=401, detail="Refresh token has expired")
    
#         # Get user role again (fresh from LDAP)
#         role = await run_in_threadpool(get_user_group, username)
#         if not role:
#             raise HTTPException(status_code=403, detail="User has no group assigned")
    
#         access_token, new_refresh_token, access_expires, refresh_expires  = create_access_tokens({"sub":username, "role": role})
    
#         # Mark current refresh token as revoked
#         token_record.is_revoked = True
#         db.commit()
    
#         log_token(username, role, access_token, new_refresh_token, access_expires, refresh_expires, request)

#     return TokenResponse(access_token=access_token, refresh_token= new_refresh_token)

@router.post("/refresh",response_model=TokenResponse)
async def refresh_token(payload: RefreshRequest, request: Request):
    try:
        decoded = decode_token(payload.refresh_token)
        username = decoded.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    redis_key = await redis_client.get(f"refresh_lookup:{payload.refresh_token}")
    if not redis_key:
        raise HTTPException(status_code=404, detail="Refresh token not found")
    
    token_data = await redis_client.get(redis_key)
    if not token_data:
        raise HTTPException(status_code=404, detail="Token not found")
    
    token_json = json.loads(token_data)
    if token_json.get("revoked"):
        raise HTTPException(status_code=401, detail="Refresh token already used")
    
    exp_time = datetime.fromisoformat(token_json["expires_at"])
    if datetime.now(timezone.utc) > exp_time:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    
    role = await run_in_threadpool(get_user_group, username)
    if not role:
        raise HTTPException(status_code=403, detail="User has no group assigned")
    
    access_token, new_refresh_token, access_expires, refresh_expires = create_access_tokens({"sub": username, "role": role})

    token_json["revoked"] = True
    await redis_client.set(redis_key, json.dumps(token_json))  # update revocation status

    await log_token(username, role, access_token, new_refresh_token, access_expires, refresh_expires, request)

    return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)

# @router.post("/logout")
# async def logout(payload: RefreshRequest):
#     with SessionLocal() as db:
#         token_record = db.query(UserToken).filter_by(refresh_token=payload.refresh_token).first()

#         if not token_record:
#             raise HTTPException(status_code=404, detail="Refresh token not found")

#         token_record.is_revoked = True
#         db.commit()
        
#     return {"detail": "User logged out successfully"}

@router.post("/logout")
async def logout(payload: RefreshRequest):
    redis_key = await redis_client.get(f"refresh_lookup:{payload.refresh_token}")
    if not redis_key:
        raise HTTPException(status_code=404, detail="Refresh token not found")

    token_data = await redis_client.get(redis_key)
    if not token_data:
        raise HTTPException(status_code=404, detail="Token not found")

    token_json = json.loads(token_data)
    token_json["revoked"] = True

    await redis_client.set(redis_key, json.dumps(token_json))
    return {"detail": "User logged out successfully"}