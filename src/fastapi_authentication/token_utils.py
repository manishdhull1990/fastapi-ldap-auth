from datetime import datetime, timedelta
from jose import jwt
from .config import settings

def create_access_tokens(data:dict, expires_delta: timedelta | None=None)-> str:
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(minutes=settings.jwt_expire_minutes))
    to_encode.update({"exp":expire})

    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    return encoded_jwt