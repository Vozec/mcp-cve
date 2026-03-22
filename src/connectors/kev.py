import httpx
from typing import Optional
from config import HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": USER_AGENT}

_kev_catalog: Optional[dict] = None


async def _load_catalog() -> dict:
    global _kev_catalog

    cache_key = "mcp_cve:kev:catalog"
    cached = await cache_get(cache_key)
    if cached is not None:
        _kev_catalog = cached
        return cached

    if _kev_catalog is not None:
        return _kev_catalog

    try:
        async with httpx.AsyncClient(timeout=30, headers=HEADERS) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        _kev_catalog = {"vulnerabilities": [], "by_cve": {}}
        return _kev_catalog

    vulns = data.get("vulnerabilities", [])
    by_cve = {}
    for v in vulns:
        cve_id = v.get("cveID", "")
        by_cve[cve_id] = {
            "cve_id": cve_id,
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "description": v.get("shortDescription", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("requiredAction", ""),
            "action": v.get("requiredAction", ""),
            "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "notes": v.get("notes", ""),
        }

    _kev_catalog = {"count": len(vulns), "by_cve": by_cve}
    await cache_set(cache_key, _kev_catalog, ttl=43200)  # 12h
    return _kev_catalog


async def is_in_kev(cve_id: str) -> bool:
    catalog = await _load_catalog()
    return cve_id in catalog.get("by_cve", {})


async def get_kev_entry(cve_id: str) -> Optional[dict]:
    catalog = await _load_catalog()
    return catalog.get("by_cve", {}).get(cve_id)


async def search_kev(keyword: str, limit: int = 20) -> list[dict]:
    catalog = await _load_catalog()
    keyword_lower = keyword.lower()
    results = []
    for cve_id, entry in catalog.get("by_cve", {}).items():
        if (
            keyword_lower in entry.get("vendor", "").lower()
            or keyword_lower in entry.get("product", "").lower()
            or keyword_lower in entry.get("name", "").lower()
            or keyword_lower in entry.get("description", "").lower()
        ):
            results.append(entry)
            if len(results) >= limit:
                break
    return results
