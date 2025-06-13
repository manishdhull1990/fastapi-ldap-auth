# src/fastapi_authentication/routes/developer.py

from fastapi import APIRouter, Depends
from ..dependencies import require_role

router = APIRouter(prefix="/developer", tags=["developer"])

@router.get("/dashboard")
def developer_dashboard(user=Depends(require_role("developers"))):
    return {"message": f"Welcome Developer {user['username']}!"}
