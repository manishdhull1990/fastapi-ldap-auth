from fastapi import FastAPI
from .auth import router as auth_router
from .routes import admin, developer, enduser

app = FastAPI(title="FastAPI LDAP Authentication")

app.include_router(auth_router)
app.include_router(admin.router)
app.include_router(developer.router)
app.include_router(enduser.router)
