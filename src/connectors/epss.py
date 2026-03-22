import httpx
from config import HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

BASE_URL = "https://api.first.org/data/v1/epss"
HEADERS = {"User-Agent": USER_AGENT}


async def get_epss(cve_id: str) -> dict:
    cache_key = make_key("epss", cve=cve_id)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=HEADERS) as client:
            resp = await client.get(BASE_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"EPSS API error: {e}"}

    entries = data.get("data", [])
    if not entries:
        return {"cve": cve_id, "score": None, "percentile": None}

    entry = entries[0]
    result = {
        "cve": entry.get("cve", cve_id),
        "score": float(entry.get("epss", 0)),
        "percentile": float(entry.get("percentile", 0)),
        "date": entry.get("date", ""),
    }
    await cache_set(cache_key, result, ttl=86400)  # 24h - EPSS updates daily
    return result


async def get_epss_batch(cve_ids: list[str]) -> list[dict]:
    if not cve_ids:
        return []

    cache_key = make_key("epss_batch", cves=",".join(sorted(cve_ids)))
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        cve_param = ",".join(cve_ids)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=HEADERS) as client:
            resp = await client.get(BASE_URL, params={"cve": cve_param})
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"EPSS API error: {e}"}]

    results = []
    for entry in data.get("data", []):
        results.append({
            "cve": entry.get("cve", ""),
            "score": float(entry.get("epss", 0)),
            "percentile": float(entry.get("percentile", 0)),
            "date": entry.get("date", ""),
        })

    await cache_set(cache_key, results, ttl=86400)
    return results
