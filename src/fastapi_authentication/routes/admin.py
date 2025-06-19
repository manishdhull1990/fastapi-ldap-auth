from fastapi import APIRouter, Depends
from ..dependencies import require_role
from ..utils.logger import logger
from ..utils.errors import handle_exception

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/dashboard")
def admin_dashboard(user: dict=Depends(require_role("admin"))):
    try:
        logger.info(f"Admin dashboard accessed by: {user['username']}")
        return {"message": f"Welcome admin {user['username']}!"}
    except Exception as e:
        handle_exception("admin_dashboard", e)