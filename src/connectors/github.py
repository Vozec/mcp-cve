import httpx
from typing import Optional
from config import GITHUB_TOKEN, HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

API_URL = "https://api.github.com"


def _headers() -> dict:
    h = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    }
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


# --- GitHub Advisory Database ---

def _parse_advisory(adv: dict) -> dict:
    vulns = adv.get("vulnerabilities", [])
    affected = []
    for v in vulns:
        pkg = v.get("package", {})
        affected.append({
            "ecosystem": pkg.get("ecosystem", ""),
            "package": pkg.get("name", ""),
            "vulnerable_range": v.get("vulnerable_version_range", ""),
            "first_patched": v.get("first_patched_version", ""),
        })

    epss = adv.get("epss", {}) or {}

    return {
        "ghsa_id": adv.get("ghsa_id", ""),
        "cve_id": adv.get("cve_id", ""),
        "summary": adv.get("summary", ""),
        "description": (adv.get("description") or "")[:500],
        "type": adv.get("type", ""),
        "severity": adv.get("severity", ""),
        "cvss_score": adv.get("cvss", {}).get("score") if adv.get("cvss") else None,
        "cvss_vector": adv.get("cvss", {}).get("vector_string") if adv.get("cvss") else None,
        "epss_score": epss.get("percentage") if epss else None,
        "epss_percentile": epss.get("percentile") if epss else None,
        "cwes": [c.get("cwe_id", "") for c in adv.get("cwes", [])],
        "affected": affected,
        "published": adv.get("published_at", ""),
        "updated": adv.get("updated_at", ""),
        "withdrawn": adv.get("withdrawn_at"),
        "url": adv.get("html_url", ""),
        "source_code_location": adv.get("source_code_location", ""),
        "references": adv.get("references", []),
    }


async def search_advisories(
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None,
    ghsa_id: Optional[str] = None,
    ecosystem: Optional[str] = None,
    severity: Optional[str] = None,
    advisory_type: Optional[str] = None,
    cwes: Optional[str] = None,
    affects: Optional[str] = None,
    sort: Optional[str] = None,
    direction: Optional[str] = None,
    per_page: int = 30,
) -> list[dict]:
    """Search GitHub Advisory Database via REST API.

    Supports full-text search via q= parameter, CVE/GHSA lookups,
    ecosystem/severity/type filters, and CWE filtering.

    Args:
        advisory_type: "reviewed" (GitHub-verified), "unreviewed" (community/third-party), "malware", or None for all.
        cwes: Comma-separated CWE IDs (e.g. "79,89,502").
        affects: Filter by affected package names.
        sort: Sort by "updated", "published", "epss_percentage", "epss_percentile".
        direction: "asc" or "desc".
    """
    cache_key = make_key(
        "gh_advisories", keyword=keyword, cve=cve_id, ghsa=ghsa_id,
        eco=ecosystem, sev=severity, type=advisory_type, cwes=cwes,
        affects=affects, sort=sort, pp=per_page,
    )
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    # REST API — supports q= for full-text search (GitHub added this parameter)
    params = {"per_page": min(per_page, 100)}
    if keyword:
        params["q"] = keyword
    if cve_id:
        params["cve_id"] = cve_id
    if ghsa_id:
        params["ghsa_id"] = ghsa_id
    if ecosystem:
        params["ecosystem"] = ecosystem
    if severity:
        params["severity"] = severity
    if advisory_type:
        params["type"] = advisory_type
    if cwes:
        params["cwes"] = cwes
    if affects:
        params["affects"] = affects
    if sort:
        params["sort"] = sort
    if direction:
        params["direction"] = direction

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(f"{API_URL}/advisories", params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitHub Advisory API error: {e}"}]

    results = [_parse_advisory(adv) for adv in (data if isinstance(data, list) else [])]

    await cache_set(cache_key, results, ttl=1800)
    return results


async def search_advisories_all_types(
    keyword: Optional[str] = None,
    ecosystem: Optional[str] = None,
    severity: Optional[str] = None,
    per_page: int = 20,
) -> dict:
    """Search advisories across all types: reviewed, unreviewed, malware.

    Uses parallel REST API calls with type filters. The q= parameter handles
    full-text keyword search for all types.
    """
    import asyncio

    def safe(val):
        if isinstance(val, Exception):
            return []
        return [r for r in val if not isinstance(r, dict) or "error" not in r]

    reviewed, unreviewed, malware = await asyncio.gather(
        search_advisories(keyword=keyword, ecosystem=ecosystem, severity=severity, advisory_type="reviewed", per_page=per_page),
        search_advisories(keyword=keyword, ecosystem=ecosystem, severity=severity, advisory_type="unreviewed", per_page=per_page),
        search_advisories(keyword=keyword, ecosystem=ecosystem, severity=severity, advisory_type="malware", per_page=min(per_page, 5)),
        return_exceptions=True,
    )

    return {
        "reviewed": safe(reviewed),
        "unreviewed": safe(unreviewed),
        "malware": safe(malware),
    }


# --- GitHub Search: PoC repos ---

async def search_poc_repos(query: str, per_page: int = 10) -> list[dict]:
    cache_key = make_key("gh_poc", query=query)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/search/repositories",
                params={"q": query, "sort": "stars", "order": "desc", "per_page": per_page},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitHub Search error: {e}"}]

    results = []
    for repo in data.get("items", []):
        results.append({
            "name": repo.get("full_name", ""),
            "description": repo.get("description", ""),
            "url": repo.get("html_url", ""),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", ""),
            "updated": repo.get("updated_at", ""),
            "topics": repo.get("topics", []),
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


# --- GitHub Search: Security Issues & PRs ---

SECURITY_LABELS = [
    "security", "vulnerability", "cve", "security-fix",
    "bug-security", "security-advisory", "exploit",
]

SECURITY_KEYWORDS = [
    "security", "vulnerability", "CVE", "exploit", "RCE",
    "injection", "XSS", "SSRF", "deserialization", "auth bypass",
    "path traversal", "privilege escalation", "buffer overflow",
]


async def search_security_issues(
    query: str,
    labels: Optional[list[str]] = None,
    state: Optional[str] = None,
    per_page: int = 15,
) -> list[dict]:
    cache_key = make_key("gh_issues", query=query, labels=labels, state=state)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    # Build search query with security context
    search_parts = [query]

    if labels:
        for label in labels:
            search_parts.append(f'label:"{label}"')

    if state:
        search_parts.append(f"state:{state}")

    search_query = " ".join(search_parts)

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/search/issues",
                params={"q": search_query, "sort": "created", "order": "desc", "per_page": per_page},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitHub Issues Search error: {e}"}]

    results = []
    for item in data.get("items", []):
        results.append({
            "title": item.get("title", ""),
            "url": item.get("html_url", ""),
            "state": item.get("state", ""),
            "type": "pull_request" if "pull_request" in item else "issue",
            "labels": [l.get("name", "") for l in item.get("labels", [])],
            "created": item.get("created_at", ""),
            "updated": item.get("updated_at", ""),
            "comments": item.get("comments", 0),
            "body_excerpt": (item.get("body") or "")[:500],
            "reactions": item.get("reactions", {}).get("total_count", 0) if item.get("reactions") else 0,
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


async def search_issues_by_label(
    repo: str,
    labels: list[str],
    state: str = "all",
    per_page: int = 20,
) -> list[dict]:
    """Search issues in a specific repo by labels (e.g., 'security', 'vulnerability')."""
    cache_key = make_key("gh_label_issues", repo=repo, labels=labels, state=state)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    label_str = ",".join(labels)

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/repos/{repo}/issues",
                params={
                    "labels": label_str,
                    "state": state,
                    "sort": "created",
                    "direction": "desc",
                    "per_page": per_page,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitHub label search error: {e}"}]

    results = []
    for item in data if isinstance(data, list) else []:
        results.append({
            "title": item.get("title", ""),
            "url": item.get("html_url", ""),
            "state": item.get("state", ""),
            "type": "pull_request" if item.get("pull_request") else "issue",
            "labels": [l.get("name", "") for l in item.get("labels", [])],
            "created": item.get("created_at", ""),
            "updated": item.get("updated_at", ""),
            "comments": item.get("comments", 0),
            "body_excerpt": (item.get("body") or "")[:500],
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


# --- GitHub Search: Security Commits ---

async def search_security_commits(
    query: str,
    per_page: int = 10,
) -> list[dict]:
    cache_key = make_key("gh_commits", query=query)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    search_query = f"{query} fix security vulnerability CVE"

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/search/commits",
                params={"q": search_query, "sort": "committer-date", "order": "desc", "per_page": per_page},
                headers={**_headers(), "Accept": "application/vnd.github.cloak-preview+json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitHub Commits Search error: {e}"}]

    results = []
    for item in data.get("items", []):
        commit = item.get("commit", {})
        results.append({
            "message": commit.get("message", "")[:200],
            "url": item.get("html_url", ""),
            "repo": item.get("repository", {}).get("full_name", ""),
            "date": commit.get("committer", {}).get("date", ""),
            "author": commit.get("author", {}).get("name", ""),
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


# --- GitHub Repo Info ---

async def get_repo_info(owner: str, repo: str) -> Optional[dict]:
    cache_key = make_key("gh_repo", owner=owner, repo=repo)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(f"{API_URL}/repos/{owner}/{repo}")
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {"error": f"GitHub Repo error: {e}"}

    result = {
        "name": data.get("full_name", ""),
        "description": data.get("description", ""),
        "url": data.get("html_url", ""),
        "language": data.get("language", ""),
        "stars": data.get("stargazers_count", 0),
        "forks": data.get("forks_count", 0),
        "open_issues": data.get("open_issues_count", 0),
        "license": data.get("license", {}).get("spdx_id") if data.get("license") else None,
        "topics": data.get("topics", []),
        "created": data.get("created_at", ""),
        "updated": data.get("updated_at", ""),
        "homepage": data.get("homepage", ""),
        "archived": data.get("archived", False),
        "default_branch": data.get("default_branch", "main"),
    }

    await cache_set(cache_key, result, ttl=3600)
    return result


# --- Search Nuclei Templates ---

async def search_nuclei_templates(query: str, per_page: int = 10) -> list[dict]:
    cache_key = make_key("gh_nuclei", query=query)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    search_query = f"{query} repo:projectdiscovery/nuclei-templates"

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/search/code",
                params={"q": search_query, "per_page": per_page},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"Nuclei search error: {e}"}]

    results = []
    for item in data.get("items", []):
        results.append({
            "name": item.get("name", ""),
            "path": item.get("path", ""),
            "url": item.get("html_url", ""),
            "repo": "projectdiscovery/nuclei-templates",
        })

    await cache_set(cache_key, results, ttl=3600)
    return results


# --- Search Metasploit Modules ---

async def search_metasploit_modules(query: str, per_page: int = 10) -> list[dict]:
    cache_key = make_key("gh_msf", query=query)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    search_query = f"{query} repo:rapid7/metasploit-framework path:modules"

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/search/code",
                params={"q": search_query, "per_page": per_page},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"Metasploit search error: {e}"}]

    results = []
    for item in data.get("items", []):
        path = item.get("path", "")
        results.append({
            "name": item.get("name", ""),
            "path": path,
            "url": item.get("html_url", ""),
            "module_type": path.split("/")[1] if "/" in path else "",
            "repo": "rapid7/metasploit-framework",
        })

    await cache_set(cache_key, results, ttl=3600)
    return results


# --- Search for Default Credentials ---

async def search_default_creds(software: str) -> list[dict]:
    cache_key = make_key("gh_defcreds", software=software)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    search_query = f"{software} repo:ihebski/DefaultCreds-cheat-sheet"

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/search/code",
                params={"q": search_query, "per_page": 5},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"Default creds search error: {e}"}]

    results = []
    for item in data.get("items", []):
        results.append({
            "name": item.get("name", ""),
            "path": item.get("path", ""),
            "url": item.get("html_url", ""),
        })

    await cache_set(cache_key, results, ttl=7200)
    return results
