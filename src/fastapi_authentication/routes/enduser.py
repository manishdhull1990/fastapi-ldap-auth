# src/fastapi_authentication/routes/enduser.py

from fastapi import APIRouter, Depends
from ..dependencies import require_role
from ..utils.logger import logger
from ..utils.errors import handle_exception

router = APIRouter(prefix="/enduser", tags=["enduser"])

@router.get("/dashboard")
def enduser_dashboard(user:dict=Depends(require_role("endusers"))):
    try:
        logger.info(f"Enduser dashboard accessed by: {user['username']}")
        return {"message": f"Welcome End User {user['username']}!"}
    except Exception as e:
        handle_exception("enduser_dashboard", e)