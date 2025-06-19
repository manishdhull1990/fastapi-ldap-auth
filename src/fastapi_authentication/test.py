import asyncio
import redis.asyncio as redis
from .config import settings

redis_client = redis.Redis(
    host="localhost",  # or "redis" if using docker-compose
    port=6379,
    db=0,
    decode_responses=True
)

# Sample test function
async def test_redis_connection():
    await redis_client.set("test_key", "Hello from FastAPI")
    value = await redis_client.get("test_key")
    print("Redis says:", value)

if __name__ == "__main__":
    asyncio.run(test_redis_connection())
print("Loaded base_dn:", settings.base_dn)
print("Redis host:", settings.redis_host)