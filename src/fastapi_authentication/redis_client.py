import redis.asyncio as redis
from .config import settings

redis_client = redis.Redis(
    host = settings.redis_host,
    port = settings.redis_port,
    db = settings.redis_db,
    decode_responses = True
)