import httpx
from typing import Optional
from config import HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

BASE_URL = "https://api.osv.dev/v1"
HEADERS = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}


def _parse_vuln(vuln: dict) -> dict:
    # Extract affected versions
    affected_list = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        ranges_info = []
        for r in aff.get("ranges", []):
            events = r.get("events", [])
            range_entry = {"type": r.get("type", "")}
            for ev in events:
                if "introduced" in ev:
                    range_entry["introduced"] = ev["introduced"]
                if "fixed" in ev:
                    range_entry["fixed"] = ev["fixed"]
            ranges_info.append(range_entry)

        affected_list.append({
            "package": pkg.get("name", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "versions": aff.get("versions", [])[:20],
            "ranges": ranges_info,
        })

    # Severity
    severity = []
    for sev in vuln.get("severity", []):
        severity.append({
            "type": sev.get("type", ""),
            "score": sev.get("score", ""),
        })

    # References
    references = [
        {"type": ref.get("type", ""), "url": ref.get("url", "")}
        for ref in vuln.get("references", [])
    ]

    # Aliases (CVE IDs etc)
    aliases = vuln.get("aliases", [])

    return {
        "id": vuln.get("id", ""),
        "summary": vuln.get("summary", ""),
        "details": vuln.get("details", "")[:1000],
        "aliases": aliases,
        "severity": severity,
        "affected": affected_list,
        "references": references,
        "published": vuln.get("published", ""),
        "modified": vuln.get("modified", ""),
        "database_url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
    }


async def query_package(
    ecosystem: str,
    package_name: str,
    version: Optional[str] = None,
) -> list[dict]:
    cache_key = make_key("osv_pkg", ecosystem=ecosystem, package=package_name, version=version)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    payload = {
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    if version:
        payload["version"] = version

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=HEADERS) as client:
            resp = await client.post(f"{BASE_URL}/query", json=payload)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"OSV API error: {e}"}]

    results = [_parse_vuln(v) for v in data.get("vulns", [])]
    await cache_set(cache_key, results, ttl=3600)
    return results


async def get_vuln(vuln_id: str) -> Optional[dict]:
    cache_key = make_key("osv_vuln", id=vuln_id)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=HEADERS) as client:
            resp = await client.get(f"{BASE_URL}/vulns/{vuln_id}")
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"OSV API error: {e}"}

    result = _parse_vuln(data)
    await cache_set(cache_key, result, ttl=3600)
    return result
