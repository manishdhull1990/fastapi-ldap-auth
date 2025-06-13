from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from .config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme))-> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        role: str = payload.get("role")

        if username is None or role is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return {"username":username, "role":role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
def require_role(required_role: str):
    def role_checker(user:dict = Depends(get_current_user)):
        if user["role"]!=required_role:
            raise HTTPException(status_code=403, detail="Access denied: Insufficient role")
        return user
    return role_checker