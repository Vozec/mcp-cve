import httpx
from typing import Optional
from config import HTTP_TIMEOUT, USER_AGENT, PROJECTDISCOVERY_API_KEY
from cache import cache_get, cache_set, make_key

CVE_API_URL = "https://cloud.projectdiscovery.io/api/v1/cves"


def _headers() -> dict:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if PROJECTDISCOVERY_API_KEY:
        h["X-Api-Key"] = PROJECTDISCOVERY_API_KEY
    return h


async def search_cves(
    keyword: Optional[str] = None,
    is_poc: Optional[bool] = None,
    is_template: Optional[bool] = None,
    severity: Optional[str] = None,
    year: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    """Search ProjectDiscovery CVE database.

    This API tracks CVEs that have Nuclei templates or known PoCs.
    Requires PROJECTDISCOVERY_API_KEY for access.
    """
    if not PROJECTDISCOVERY_API_KEY:
        return {"error": "PROJECTDISCOVERY_API_KEY not configured", "cves": [], "total": 0}

    cache_key = make_key(
        "nuclei_cve", keyword=keyword, poc=is_poc, template=is_template,
        severity=severity, year=year, limit=limit, offset=offset,
    )
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    params = {
        "limit": min(limit, 100),
        "offset": offset,
    }
    if keyword:
        params["search"] = keyword
    if is_poc is not None:
        params["is_poc"] = str(is_poc).lower()
    if is_template is not None:
        params["is_template"] = str(is_template).lower()
    if severity:
        params["severity"] = severity.lower()
    if year:
        params["published_at_gt"] = year

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(CVE_API_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"ProjectDiscovery API error: {e}", "cves": [], "total": 0}

    cves = data if isinstance(data, list) else data.get("cves", [])

    results = []
    for cve in cves:
        results.append({
            "cve_id": cve.get("cve_id", ""),
            "description": (cve.get("cve_description", "") or "")[:300],
            "severity": cve.get("severity", ""),
            "cvss_score": cve.get("cvss_score"),
            "cvss_metrics": cve.get("cvss_metrics", ""),
            "is_poc": cve.get("is_poc", False),
            "is_template": cve.get("is_template", False),
            "is_exploited": cve.get("is_exploited", False),
            "poc_urls": cve.get("poc", []) or [],
            "nuclei_template_url": cve.get("nuclei_template_url", ""),
            "published": cve.get("published_at", ""),
            "vendor": cve.get("vendor_advisory", ""),
            "weaknesses": cve.get("weaknesses", []),
            "epss_score": cve.get("epss", {}).get("epss_score") if cve.get("epss") else None,
        })

    result = {"total": len(results), "cves": results}
    await cache_set(cache_key, result, ttl=1800)
    return result


async def search_templates(keyword: str, limit: int = 20) -> dict:
    """Search for CVEs that have Nuclei templates available."""
    return await search_cves(keyword=keyword, is_template=True, limit=limit)


async def search_pocs(keyword: str, limit: int = 20) -> dict:
    """Search for CVEs that have known PoCs."""
    return await search_cves(keyword=keyword, is_poc=True, limit=limit)
