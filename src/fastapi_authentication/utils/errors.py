from fastapi import HTTPException
from .logger import logger
import traceback

def handle_exception(context: str, exc: Exception):
    logger.error(f"{context} - Exception: {str(exc)}")
    logger.debug(traceback.format_exc())
    raise HTTPException(status_code=500, detail=f"Internal Server Error in {context}")
