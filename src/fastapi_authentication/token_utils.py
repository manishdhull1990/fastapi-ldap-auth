from datetime import datetime, timedelta, timezone
from jose import jwt,JWTError
from fastapi import HTTPException, status
from .config import settings
from .models_database.token_log import UserToken
from .database import SessionLocal

def _create_token(data:dict, expires_delta: timedelta)->str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    return encoded_jwt

def create_access_tokens(data:dict)-> tuple[str,str,timedelta,timedelta]:
    access_expires = timedelta(minutes=settings.jwt_expire_minutes)
    refresh_expires = timedelta(days=settings.jwt_expire_expire_days)
    
    access_token = _create_token(data, access_expires)

    refresh_data = {"sub": data["sub"]}
    refresh_token = _create_token(refresh_data, refresh_expires)
    
    return access_token, refresh_token, access_expires, refresh_expires

def decode_token(token: str)-> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError as e:
        raise HTTPException(status_code = status.HTTP_403_FORBIDDEN,
                            detail = "Invalid or expired token") from e

def log_token(username, role, access_token, refresh_token, expires_delta, refresh_expires, request):
    db = None
    close_db = False
    try:
        db = SessionLocal()
        token = UserToken(
            username=username,
            role=role,
            access_token=access_token,
            refresh_token=refresh_token,
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + expires_delta,
            refresh_expires_at=datetime.now(timezone.utc) + refresh_expires,
            ip_address=request.client.host if request else None,
            user_agent=request.headers.get("user-agent") if request else None,
        )
        db.add(token)
        db.commit()
    except Exception as e:
        raise RuntimeError(f"Failed to log token: {e}")
    finally:
        if db:
            db.close()
