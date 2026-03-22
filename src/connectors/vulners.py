import httpx
from typing import Optional
from config import HTTP_TIMEOUT, USER_AGENT, VULNERS_API_KEY
from cache import cache_get, cache_set, make_key

API_URL = "https://vulners.com/api/v3"


def _headers() -> dict:
    h = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if VULNERS_API_KEY:
        h["X-Api-Key"] = VULNERS_API_KEY
    return h


async def search(
    query: str,
    limit: int = 20,
    skip: int = 0,
    fields: Optional[list[str]] = None,
) -> dict:
    """Search Vulners using Lucene query syntax.

    Query examples:
        - "Apache Tomcat RCE"
        - "title:*liferay* bulletinFamily:exploit"
        - "CVE-2024-1234"
        - "(affectedPackage.packageName:log4j*) OR (title:log4j* AND bulletinFamily:exploit)"
    """
    cache_key = make_key("vulners_search", query=query, limit=limit, skip=skip)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    payload = {
        "query": query,
        "skip": skip,
        "size": min(limit, 50),
    }
    if fields:
        payload["fields"] = fields

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.post(f"{API_URL}/search/lucene/", json=payload)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"Vulners API error: {e}"}

    if data.get("result") != "OK":
        return {"error": data.get("data", {}).get("error", "Unknown Vulners error")}

    search_data = data.get("data", {})
    documents = search_data.get("search", [])

    results = []
    for doc in documents:
        src = doc.get("_source", {})
        results.append({
            "id": src.get("id", ""),
            "title": src.get("title", ""),
            "description": (src.get("description", "") or "")[:300],
            "type": src.get("type", ""),
            "bulletin_family": src.get("bulletinFamily", ""),
            "cvss_score": src.get("cvss", {}).get("score") if src.get("cvss") else None,
            "cvss3_score": src.get("cvss3", {}).get("cvssV3", {}).get("baseScore") if src.get("cvss3") else None,
            "published": src.get("published", ""),
            "href": src.get("href", ""),
            "source_href": src.get("sourceHref", ""),
            "cve_list": src.get("cvelist", []),
        })

    result = {
        "total": search_data.get("total", 0),
        "results": results,
    }

    await cache_set(cache_key, result, ttl=1800)
    return result


async def search_exploits(software: str, limit: int = 20) -> dict:
    """Search specifically for exploits related to a software."""
    query = f"{software} bulletinFamily:exploit order:published"
    return await search(query=query, limit=limit)


async def search_by_cve(cve_id: str, limit: int = 10) -> dict:
    """Search all Vulners entries related to a CVE."""
    return await search(query=cve_id, limit=limit)


async def get_by_id(vuln_id: str) -> dict:
    """Fetch a specific vulnerability by its Vulners ID."""
    cache_key = make_key("vulners_id", id=vuln_id)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.post(
                f"{API_URL}/search/id/",
                json={"id": vuln_id},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"Vulners API error: {e}"}

    if data.get("result") != "OK":
        return {"error": data.get("data", {}).get("error", "Unknown error")}

    doc = data.get("data", {}).get("documents", {}).get(vuln_id, {})
    result = {
        "id": doc.get("id", ""),
        "title": doc.get("title", ""),
        "description": (doc.get("description", "") or "")[:1000],
        "type": doc.get("type", ""),
        "bulletin_family": doc.get("bulletinFamily", ""),
        "cvss_score": doc.get("cvss", {}).get("score") if doc.get("cvss") else None,
        "published": doc.get("published", ""),
        "href": doc.get("href", ""),
        "source_href": doc.get("sourceHref", ""),
        "cve_list": doc.get("cvelist", []),
        "references": doc.get("references", []),
    }

    await cache_set(cache_key, result, ttl=3600)
    return result
