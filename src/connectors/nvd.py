import httpx
from typing import Optional
from config import NVD_API_KEY, HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _headers() -> dict:
    h = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _parse_cve(item: dict) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # CVSS v3.1
    metrics = cve.get("metrics", {})
    cvss_data = {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            primary = next(
                (m for m in metrics[key] if m.get("type") == "Primary"),
                metrics[key][0],
            )
            cd = primary.get("cvssData", {})
            cvss_data = {
                "score": cd.get("baseScore"),
                "severity": cd.get("baseSeverity"),
                "vector": cd.get("vectorString"),
                "attack_vector": cd.get("attackVector"),
                "attack_complexity": cd.get("attackComplexity"),
                "privileges_required": cd.get("privilegesRequired"),
                "user_interaction": cd.get("userInteraction"),
                "scope": cd.get("scope"),
                "confidentiality": cd.get("confidentialityImpact"),
                "integrity": cd.get("integrityImpact"),
                "availability": cd.get("availabilityImpact"),
            }
            cvss_data["exploitability_score"] = primary.get("exploitabilityScore")
            cvss_data["impact_score"] = primary.get("impactScore")
            break

    # CWE
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    # CPE affected
    affected_configs = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    entry = {"cpe": match.get("criteria", "")}
                    if "versionStartIncluding" in match:
                        entry["version_start"] = match["versionStartIncluding"]
                    if "versionEndIncluding" in match:
                        entry["version_end_including"] = match["versionEndIncluding"]
                    if "versionEndExcluding" in match:
                        entry["version_end_excluding"] = match["versionEndExcluding"]
                    affected_configs.append(entry)

    # References
    references = [
        {"url": ref.get("url", ""), "source": ref.get("source", ""), "tags": ref.get("tags", [])}
        for ref in cve.get("references", [])
    ]

    # Extract exploit references
    exploit_refs = [
        ref for ref in references
        if any(t in ref.get("tags", []) for t in ("Exploit", "Third Party Advisory"))
        or "exploit-db.com" in ref.get("url", "")
        or "packetstormsecurity" in ref.get("url", "")
    ]

    return {
        "cve_id": cve_id,
        "description": desc_en,
        "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""),
        "cvss": cvss_data,
        "cwes": cwes,
        "affected": affected_configs,
        "references": references,
        "exploit_references": exploit_refs,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


async def search_cves(
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None,
    cpe_name: Optional[str] = None,
    severity: Optional[str] = None,
    cwe_id: Optional[str] = None,
    results_per_page: int = 20,
    start_index: int = 0,
) -> list[dict]:
    cache_key = make_key(
        "nvd_search", keyword=keyword, cve_id=cve_id, cpe_name=cpe_name,
        severity=severity, cwe_id=cwe_id, rpp=results_per_page, start=start_index,
    )
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    params = {"resultsPerPage": results_per_page, "startIndex": start_index}
    if keyword:
        params["keywordSearch"] = keyword
    if cve_id:
        params["cveId"] = cve_id
    if cpe_name:
        params["cpeName"] = cpe_name
    if severity:
        params["cvssV3Severity"] = severity.upper()
    if cwe_id:
        params["cweId"] = cwe_id

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(BASE_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"NVD API error: {e}"}]

    results = [_parse_cve(item) for item in data.get("vulnerabilities", [])]
    await cache_set(cache_key, results, ttl=1800)
    return results


async def get_cve(cve_id: str) -> Optional[dict]:
    results = await search_cves(cve_id=cve_id, results_per_page=1)
    if results and "error" not in results[0]:
        return results[0]
    return None
