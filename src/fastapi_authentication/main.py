from fastapi import FastAPI
from .auth import router as auth_router

app = FastAPI(title="FastAPI LDAP Authentication")

app.include_router(auth_router)