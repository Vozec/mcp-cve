import httpx
from typing import Optional
from config import SHODAN_API_KEY, HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

API_URL = "https://api.shodan.io"
HEADERS = {"User-Agent": USER_AGENT}


async def count(query: str, facets: str = "country:10,version:10,os:5,port:10") -> dict:
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not configured", "dork": query}

    cache_key = make_key("shodan_count", query=query, facets=facets)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=HEADERS) as client:
            resp = await client.get(
                f"{API_URL}/shodan/host/count",
                params={"key": SHODAN_API_KEY, "query": query, "facets": facets},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"Shodan API error: {e}", "dork": query}

    facets_result = {}
    for facet_name, values in data.get("facets", {}).items():
        facets_result[facet_name] = [
            {"value": v.get("value", ""), "count": v.get("count", 0)}
            for v in values
        ]

    result = {
        "query": query,
        "total": data.get("total", 0),
        "facets": facets_result,
    }

    await cache_set(cache_key, result, ttl=3600)
    return result


async def search(query: str, page: int = 1) -> dict:
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not configured", "dork": query}

    cache_key = make_key("shodan_search", query=query, page=page)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=HEADERS) as client:
            resp = await client.get(
                f"{API_URL}/shodan/host/search",
                params={"key": SHODAN_API_KEY, "query": query, "page": page},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"Shodan API error: {e}", "dork": query}

    matches = []
    for m in data.get("matches", [])[:20]:
        matches.append({
            "ip": m.get("ip_str", ""),
            "port": m.get("port", 0),
            "org": m.get("org", ""),
            "hostnames": m.get("hostnames", []),
            "os": m.get("os", ""),
            "product": m.get("product", ""),
            "version": m.get("version", ""),
            "country": m.get("location", {}).get("country_name", ""),
            "banner_excerpt": (m.get("data") or "")[:200],
        })

    result = {
        "query": query,
        "total": data.get("total", 0),
        "matches": matches,
    }

    await cache_set(cache_key, result, ttl=3600)
    return result
