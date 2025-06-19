from fastapi import APIRouter, HTTPException, Depends,Request
from fastapi.security import OAuth2PasswordRequestForm
from starlette.concurrency import run_in_threadpool
from .ldap_utils import authenticate_user, get_user_group
from .models import LoginRequest, TokenResponse, RefreshRequest
from .token_utils import create_access_tokens, decode_token, log_token
from .redis_client import redis_client
from .utils.logger import logger  
from .utils.errors import handle_exception

import json
# from sqlalchemy.orm import Session
# from .database import SessionLocal
# from .models_database.token_log import UserToken

from datetime import datetime, timezone

router = APIRouter()

@router.post("/login",response_model=TokenResponse)
async def login_user(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        username = form_data.username
        password = form_data.password
        is_valid = await run_in_threadpool(authenticate_user, username, password)
        if not is_valid:
            logger.warning(f"Login failed - Invalid credentials for user: {username}, IP: {request.client.host}")
            raise HTTPException(status_code=401, detail="Invalid username and password")
        logger.info(f"LDAP auth succeeded for user: {username}")

        try:
            role = await run_in_threadpool(get_user_group, username)
        except LDAPAuthError as e:
            # Log the LDAP error with stack trace
            logger.error(f"LDAP group fetch error for user {username}: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
        
        if not role:
            logger.warning(f"Login failed - No group assigned to user: {username}")
            raise HTTPException(status_code=403, detail="User has no group assigned")
        logger.info(f"Group '{role}' found for user: {username}")

        access_token, refresh_token, access_expires, refresh_expires = create_access_tokens({"sub":username, "role":role})
        await log_token(username, role, access_token, refresh_token, access_expires, refresh_expires, request)
        logger.info(f"Login success - user: {username}, role: {role}, IP: {request.client.host}")
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)
    except HTTPException:
        raise
    except Exception as e:
        return handle_exception("Login", e)

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
        if not username:
            logger.warning(f"Refresh failed - Missing subject in token")
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        redis_key = await redis_client.get(f"refresh_lookup:{payload.refresh_token}")
        if not redis_key:
            logger.warning(f"Refresh failed - Token lookup not found for user: {username}")
            raise HTTPException(status_code=404, detail="Refresh token not found")
        
        token_data = await redis_client.get(redis_key)
        if not token_data:
            logger.warning(f"Refresh failed - Token data not found for key: {redis_key}")
            raise HTTPException(status_code=404, detail="Token not found")
        
        token_json = json.loads(token_data)
        if token_json.get("revoked"):
            logger.warning(f"Refresh failed - Token already used for user: {username}")
            raise HTTPException(status_code=401, detail="Refresh token already used")
        
        exp_time = datetime.fromisoformat(token_json["expires_at"])
        if datetime.now(timezone.utc) > exp_time:
            raise HTTPException(status_code=401, detail="Refresh token expired")
        
        try:
            role = await run_in_threadpool(get_user_group, username)
        except LDAPAuthError as e:
            logger.error(f"LDAP group fetch error during refresh for user {username}: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
        if not role:
            logger.warning(f"Refresh failed - Token expired for user: {username}")
            raise HTTPException(status_code=401, detail="Refresh token expired")
        
        # Generate new tokens
        access_token, new_refresh_token, access_expires, refresh_expires = create_access_tokens({"sub": username, "role": role})
        # Revoke old token
        token_json["revoked"] = True
        await redis_client.set(redis_key, json.dumps(token_json))  # update revocation status

        await log_token(username, role, access_token, new_refresh_token, access_expires, refresh_expires, request)
        
        logger.info(f"Refresh success - user: {username}, new token issued, IP: {request.client.host}")
        return TokenResponse(access_token=access_token, refresh_token=new_refresh_token)
    except HTTPException:
        raise
    except Exception as e:
        return handle_exception("Refresh", e)

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
async def logout(payload: RefreshRequest, request: Request):
    try:
        redis_key = await redis_client.get(f"refresh_lookup:{payload.refresh_token}")
        if not redis_key:
            raise HTTPException(status_code=404, detail="Refresh token not found")

        token_data = await redis_client.get(redis_key)
        if not token_data:
            raise HTTPException(status_code=404, detail="Token not found")

        token_json = json.loads(token_data)
        token_json["revoked"] = True

        await redis_client.set(redis_key, json.dumps(token_json))
        logger.info(f"Logout - user: {token_json['username']}, token revoked, IP: {request.client.host}")
        return {"detail": "User logged out successfully"}
    except HTTPException:
        raise
    except Exception as e:
        return handle_exception("Logout", e)