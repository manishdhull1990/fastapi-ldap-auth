from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from .ldap_utils import authenticate_user

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
def login_user(login: LoginRequest):
    is_authenticated = authenticate_user(login.username, login.password)
    if not is_authenticated:
        raise HTTPException(status_code=401, detail="Invalid username and password")
    
    return {"message":"Login successful"}