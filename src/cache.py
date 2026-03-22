import json
import hashlib
from typing import Optional

from config import REDIS_URL

_redis = None
_initialized = False


async def _get_redis():
    global _redis, _initialized
    if _initialized:
        return _redis
    _initialized = True
    try:
        from redis.asyncio import Redis
        _redis = Redis.from_url(REDIS_URL, decode_responses=True)
        await _redis.ping()
        return _redis
    except Exception:
        _redis = None
        return None


def make_key(prefix: str, **kwargs) -> str:
    raw = json.dumps(kwargs, sort_keys=True, default=str)
    h = hashlib.md5(raw.encode()).hexdigest()[:12]
    return f"mcp_cve:{prefix}:{h}"


async def cache_get(key: str) -> Optional[dict]:
    r = await _get_redis()
    if r is None:
        return None
    try:
        data = await r.get(key)
        if data:
            return json.loads(data)
    except Exception:
        pass
    return None


async def cache_set(key: str, value, ttl: int = 3600):
    r = await _get_redis()
    if r is None:
        return
    try:
        await r.set(key, json.dumps(value, default=str), ex=ttl)
    except Exception:
        pass
