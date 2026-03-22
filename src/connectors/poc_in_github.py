import httpx
from config import GITHUB_TOKEN, HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

# nomi-sec/PoC-in-GitHub - aggregated PoC database
REPO = "nomi-sec/PoC-in-GitHub"
API_URL = "https://api.github.com"
RAW_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"


def _headers() -> dict:
    h = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


async def search_poc(cve_id: str) -> list[dict]:
    """Search PoC-in-GitHub for a specific CVE.

    The repo stores JSON files per CVE at /{year}/CVE-YYYY-NNNNN.json
    Each file contains a list of GitHub repos that are PoCs.
    """
    cache_key = make_key("poc_gh", cve=cve_id)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    # Extract year from CVE ID
    parts = cve_id.split("-")
    if len(parts) < 3:
        return []

    year = parts[1]
    file_url = f"{RAW_URL}/{year}/{cve_id}.json"

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(file_url)
            if resp.status_code == 404:
                await cache_set(cache_key, [], ttl=3600)
                return []
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []

    results = []
    for poc in data if isinstance(data, list) else []:
        results.append({
            "name": poc.get("full_name", ""),
            "description": poc.get("description", ""),
            "url": poc.get("html_url", ""),
            "stars": poc.get("stargazers_count", 0),
            "forks": poc.get("forks_count", 0),
            "created": poc.get("created_at", ""),
            "updated": poc.get("updated_at", ""),
            "language": poc.get("language", ""),
        })

    # Sort by stars desc
    results.sort(key=lambda x: x.get("stars", 0), reverse=True)
    await cache_set(cache_key, results, ttl=3600)
    return results


async def list_cves_by_year(year: str, limit: int = 30) -> list[str]:
    """List available CVE PoCs for a given year from the repo directory."""
    cache_key = make_key("poc_gh_year", year=year)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/repos/{REPO}/contents/{year}",
                params={"per_page": 100},
            )
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []

    cve_ids = []
    for item in data if isinstance(data, list) else []:
        name = item.get("name", "")
        if name.startswith("CVE-") and name.endswith(".json"):
            cve_ids.append(name.replace(".json", ""))

    # Return the most recent ones (sorted reverse)
    cve_ids.sort(reverse=True)
    result = cve_ids[:limit]
    await cache_set(cache_key, result, ttl=3600)
    return result
