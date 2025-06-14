from datetime import datetime, timedelta, timezone
from jose import jwt,JWTError
from fastapi import HTTPException, status
from .config import settings

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

def create_access_tokens(data:dict)-> tuple[str,str]:
    access_expires = timedelta(minutes=settings.jwt_expire_minutes)
    refresh_expires = timedelta(days=settings.jwt_expire_expire_days)
    
    access_token = _create_token(data, access_expires)

    refresh_data = {"sub": data["sub"]}
    refresh_token = _create_token(refresh_data, refresh_expires)
    
    return access_token, refresh_token

def decode_token(token: str)-> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError as e:
        raise HTTPException(status_code = status.HTTP_403_FORBIDDEN,
                            detail = "Invalid or expired token") from e