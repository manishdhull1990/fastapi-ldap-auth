# src/fastapi_authentication/routes/developer.py

from fastapi import APIRouter, Depends
from ..dependencies import require_role
from ..utils.logger import logger
from ..utils.errors import handle_exception

router = APIRouter(prefix="/developer", tags=["developer"])

@router.get("/dashboard")
def developer_dashboard(user=Depends(require_role("developers"))):
    try:
        logger.info(f"Developer dashboard accessed by: {user['username']}")
        return {"message": f"Welcome Developer {user['username']}!"}
    except Exception as e:
        handle_exception("developer_dashboard", e)
