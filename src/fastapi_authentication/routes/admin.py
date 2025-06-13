from fastapi import APIRouter, Depends
from ..dependencies import require_role

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/dashboard")
def admin_dashboard(user=Depends(require_role("admin"))):
    return {"message": f"Welcome admin {user['username']}!"}