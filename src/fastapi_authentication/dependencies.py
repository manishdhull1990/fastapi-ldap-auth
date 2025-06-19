from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from .config import settings
from .utils.logger import logger
from .utils.errors import handle_exception

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme))-> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        role: str = payload.get("role")

        if username is None or role is None:
            logger.warning("Token payload missing 'sub' or 'role'")
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        logger.info(f"Token verified for user: {username}, role: {role}")
        return {"username":username, "role":role}
    except JWTError as e:
        logger.warning(f"JWT decode failed: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        handle_exception("get_current_user", e)

def require_role(required_role: str):
    def role_checker(user:dict = Depends(get_current_user)):
        try:
            if user["role"]!=required_role:
                logger.warning(f"Access denied for user: {user['username']} - \
                               Required role:{required_role}, Found: {user['role']}")
                raise HTTPException(status_code=403, detail="Access denied: Insufficient role")
            return user
        except Exception as e:
            handle_exception("require_role", e)
    return role_checker