# src/fastapi_authentication/routes/enduser.py

from fastapi import APIRouter, Depends
from ..dependencies import require_role

router = APIRouter(prefix="/enduser", tags=["enduser"])

@router.get("/dashboard")
def enduser_dashboard(user=Depends(require_role("endusers"))):
    return {"message": f"Welcome End User {user['username']}!"}
