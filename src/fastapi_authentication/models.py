from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    message: str
    username: str
    role: str| None = None

class TokenResponse(BaseModel):
    access_token:str
    token_type:str ="bearer"