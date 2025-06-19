from datetime import datetime, timedelta, timezone
from jose import jwt,JWTError
from fastapi import HTTPException, status
from .config import settings
from .models_database.token_log import UserToken
from .database import SessionLocal
from .redis_client import redis_client
import uuid
import json
from .utils.logger import logger 
import traceback 
from .utils.errors import handle_exception

def _create_token(data:dict, expires_delta: timedelta)->str:
    try:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": expire})

        encoded_jwt = jwt.encode(
            to_encode,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm
        )
        return encoded_jwt
    except Exception as e:
        handle_exception("Token Creation (_create_token)", e)

def create_access_tokens(data:dict)-> tuple[str,str,timedelta,timedelta]:
    try:
        access_expires = timedelta(minutes=settings.jwt_expire_minutes)
        refresh_expires = timedelta(days=settings.jwt_expire_expire_days)
        
        access_token = _create_token(data, access_expires)

        refresh_data = {"sub": data["sub"]}
        refresh_token = _create_token(refresh_data, refresh_expires)
        
        return access_token, refresh_token, access_expires, refresh_expires
    except Exception as e:
        handle_exception("Token Generation (create_access_tokens)", e)

def decode_token(token: str)-> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError as e:
        logger.warning("JWT decode error:\n%s", traceback.format_exc())
        raise HTTPException(status_code = status.HTTP_403_FORBIDDEN,
                            detail = "Invalid or expired token") from e
    except Exception as e:
         handle_exception("Token Decoding", e)

# def log_token(username, role, access_token, refresh_token, expires_delta, refresh_expires, request):
#     db = None
#     close_db = False
#     try:
#         db = SessionLocal()
#         token = UserToken(
#             username=username,
#             role=role,
#             access_token=access_token,
#             refresh_token=refresh_token,
#             issued_at=datetime.now(timezone.utc),
#             expires_at=datetime.now(timezone.utc) + expires_delta,
#             refresh_expires_at=datetime.now(timezone.utc) + refresh_expires,
#             ip_address=request.client.host if request else None,
#             user_agent=request.headers.get("user-agent") if request else None,
#         )
#         db.add(token)
#         db.commit()
#     except Exception as e:
#         raise RuntimeError(f"Failed to log token: {e}")
#     finally:
#         if db:
#             db.close()

async def log_token(username, role, access_token, refresh_token, access_expires, refresh_expires, request):
    try:
        ip = request.client.host if request else None
        user_agent = request.headers.get("user-agent") if request else None

        issued_at = datetime.now(timezone.utc)
        access_exp = issued_at + access_expires
        refresh_exp = issued_at + refresh_expires

        # # Debug precision display
        # print("\n--- Token Timing Debug ---")
        # print("Issued at      :", issued_at.isoformat(timespec="microseconds"))
        # print("Access expires :", access_exp.isoformat(timespec="microseconds"))
        # print("Refresh expires:", refresh_exp.isoformat(timespec="microseconds"))
        # print("Access TTL (s) :", (access_exp - issued_at).total_seconds())
        # print("Refresh TTL (s):", (refresh_exp - issued_at).total_seconds())
        # print("--------------------------\n")

        jti = str(uuid.uuid4())
        access_token_key = f"access:{jti}"
        refresh_token_key = f"refresh:{jti}"
        lookup_key = f"refresh_lookup:{refresh_token}"

        access_data = {
            "username" : username,
            "role" : role,
            "issued_at": issued_at.isoformat(timespec="microseconds"),
            "expires_at": access_exp.isoformat(timespec="microseconds"),
            "ip": ip,
            "user_agent": user_agent
        }

        refresh_data = {
            "username": username,
            "role": role,
            "issued_at": issued_at.isoformat(timespec="microseconds"),
            "expires_at": refresh_exp.isoformat(timespec="microseconds"),
            "ip": ip,
            "user_agent": user_agent,
            "revoked": False
        }
        await redis_client.set(access_token_key, json.dumps(access_data), ex=access_expires)
        await redis_client.set(refresh_token_key, json.dumps(refresh_data), ex=refresh_expires)
        await redis_client.set(lookup_key, refresh_token_key, ex=refresh_expires)
        logger.info(
            f"Token issued - user: {username}, role: {role}, IP: {ip}, jti: {jti}, "
            f"access_ttl: {access_expires.total_seconds()}s, refresh_ttl: {refresh_expires.total_seconds()}s"
        )
    except Exception as e:
        handle_exception("Token Logging (log_token)", e)