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


async def _rest_advisories(
    advisory_type: Optional[str] = None,
    ecosystem: Optional[str] = None,
    severity: Optional[str] = None,
    affects: Optional[str] = None,
    per_page: int = 30,
) -> list[dict]:
    """Raw REST /advisories call — no keyword support, used internally."""
    params: dict = {"per_page": min(per_page, 100)}
    if advisory_type:
        params["type"] = advisory_type
    if ecosystem:
        params["ecosystem"] = ecosystem
    if severity:
        params["severity"] = severity
    if affects:
        params["affects"] = affects
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(f"{API_URL}/advisories", params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []
    return [_parse_advisory(adv) for adv in (data if isinstance(data, list) else [])]


async def _fetch_advisory_by_ghsa(client: httpx.AsyncClient, ghsa_id: str) -> Optional[dict]:
    """Fetch a single advisory by GHSA ID via REST."""
    try:
        resp = await client.get(f"{API_URL}/advisories/{ghsa_id}")
        if resp.status_code == 200:
            return _parse_advisory(resp.json())
    except Exception:
        pass
    return None


async def _search_advisories_by_code_search(
    keyword: str,
    advisory_type: Optional[str] = None,
    ecosystem: Optional[str] = None,
    severity: Optional[str] = None,
    per_page: int = 20,
) -> list[dict]:
    """Full-text search on github/advisory-database via Code Search API.

    This mirrors github.com/advisories?query=<keyword> — same underlying data.
    Extracts GHSA IDs from file paths, then fetches advisory details in parallel.
    """
    import asyncio
    import re

    # Build code search query on the advisory-database repo
    q = f"{keyword} repo:github/advisory-database"
    # Optional path-based type filter
    if advisory_type:
        type_path_map = {
            "reviewed": "advisories/github-reviewed",
            "unreviewed": "advisories/unreviewed",
            "malware": "advisories/github-reviewed/malware",
        }
        path_prefix = type_path_map.get(advisory_type)
        if path_prefix:
            q += f" path:{path_prefix}"

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/search/code",
                params={"q": q, "per_page": min(per_page, 30)},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
    except Exception:
        return []

    # Extract GHSA IDs from file paths
    # e.g. "advisories/github-reviewed/2023/02/GHSA-xxxx-xxxx-xxxx/GHSA-xxxx-xxxx-xxxx.json"
    ghsa_pattern = re.compile(r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)
    ghsa_ids: list[str] = []
    seen_ids: set = set()
    for item in data.get("items", []):
        path = item.get("path", "") + " " + item.get("name", "")
        for match in ghsa_pattern.finditer(path):
            ghsa_id = match.group(1).upper()
            if ghsa_id not in seen_ids:
                seen_ids.add(ghsa_id)
                ghsa_ids.append(ghsa_id)
                if len(ghsa_ids) >= per_page:
                    break
        if len(ghsa_ids) >= per_page:
            break

    if not ghsa_ids:
        return []

    # Fetch all matched advisories in parallel
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
        advisories = await asyncio.gather(
            *[_fetch_advisory_by_ghsa(client, gid) for gid in ghsa_ids],
            return_exceptions=True,
        )

    results = []
    for adv in advisories:
        if not isinstance(adv, dict) or not adv:
            continue
        if severity and adv.get("severity", "").lower() != severity.lower():
            continue
        if ecosystem:
            pkgs = [a.get("ecosystem", "").lower() for a in adv.get("affected", [])]
            if ecosystem.lower() not in pkgs:
                continue
        results.append(adv)

    return results


async def _search_advisories_by_keyword(
    keyword: str,
    advisory_type: Optional[str] = None,
    ecosystem: Optional[str] = None,
    severity: Optional[str] = None,
    per_page: int = 20,
) -> list[dict]:
    """Keyword search on GitHub Advisory Database.

    Runs two strategies in parallel and merges results:
    1. Code Search on github/advisory-database — full-text, same source as github.com/advisories
    2. REST /advisories?affects=<keyword> — package name match (fast, catches ecosystem packages)

    Results are deduplicated by GHSA ID, code search results ranked first.
    """
    import asyncio

    code_results, affects_results = await asyncio.gather(
        _search_advisories_by_code_search(
            keyword=keyword, advisory_type=advisory_type,
            ecosystem=ecosystem, severity=severity, per_page=per_page,
        ),
        _rest_advisories(
            advisory_type=advisory_type, ecosystem=ecosystem,
            severity=severity, affects=keyword, per_page=per_page,
        ),
        return_exceptions=True,
    )

    seen: set = set()
    results: list = []

    for batch in [code_results, affects_results]:
        if isinstance(batch, Exception) or not isinstance(batch, list):
            continue
        for r in batch:
            ghsa = r.get("ghsa_id", "")
            if not ghsa or ghsa in seen:
                continue
            seen.add(ghsa)
            results.append(r)

    return results[:per_page]


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
    """Search GitHub Advisory Database.

    Uses Code Search on github/advisory-database for keyword queries (accurate, same
    source as github.com/advisories). Falls back to REST API for precise lookups
    (CVE ID, GHSA ID, ecosystem, CWE filters).

    Args:
        advisory_type: "reviewed" (GitHub-verified), "unreviewed" (community/third-party), "malware", or None for all.
        cwes: Comma-separated CWE IDs (e.g. "79,89,502").
        affects: Filter by affected package names.
        sort: Sort by "updated", "published", "epss_percentage", "epss_percentile".
        direction: "asc" or "desc".
    """
    cache_key = make_key(
        "gh_advisories2", keyword=keyword, cve=cve_id, ghsa=ghsa_id,
        eco=ecosystem, sev=severity, type=advisory_type, cwes=cwes,
        affects=affects, sort=sort, pp=per_page,
    )
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    # Keyword search: use Code Search on the advisory-database repo
    if keyword and not cve_id and not ghsa_id:
        results = await _search_advisories_by_keyword(
            keyword=keyword, advisory_type=advisory_type,
            ecosystem=ecosystem, severity=severity, per_page=per_page,
        )
        await cache_set(cache_key, results, ttl=1800)
        return results

    # Precise lookup: REST API (CVE ID, GHSA ID, ecosystem, CWE, type filters)
    params = {"per_page": min(per_page, 100)}
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

    When a keyword is given, uses parallel Code Search calls per type (accurate).
    Without a keyword, uses parallel REST calls with type filters.
    """
    import asyncio

    def safe(val):
        if isinstance(val, Exception):
            return []
        return [r for r in val if not isinstance(r, dict) or "error" not in r]

    if keyword:
        # Parallel Code Search — one per type for accurate results
        reviewed, unreviewed, malware = await asyncio.gather(
            _search_advisories_by_keyword(keyword=keyword, advisory_type="reviewed", ecosystem=ecosystem, severity=severity, per_page=per_page),
            _search_advisories_by_keyword(keyword=keyword, advisory_type="unreviewed", ecosystem=ecosystem, severity=severity, per_page=per_page),
            _search_advisories_by_keyword(keyword=keyword, advisory_type="malware", ecosystem=ecosystem, severity=severity, per_page=min(per_page, 5)),
            return_exceptions=True,
        )
    else:
        # No keyword: REST API with type filters
        reviewed, unreviewed, malware = await asyncio.gather(
            search_advisories(ecosystem=ecosystem, severity=severity, advisory_type="reviewed", per_page=per_page),
            search_advisories(ecosystem=ecosystem, severity=severity, advisory_type="unreviewed", per_page=per_page),
            search_advisories(ecosystem=ecosystem, severity=severity, advisory_type="malware", per_page=min(per_page, 5)),
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


async def search_repo_security_advisories(
    repo: str,
    per_page: int = 20,
) -> list[dict]:
    """Fetch security advisories from a specific repo's Security tab (GHSA).

    Calls GET /repos/{owner}/{repo}/security-advisories.
    Returns [] for repos with no published security advisories or missing access.
    """
    cache_key = make_key("gh_repo_sec_adv", repo=repo)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                f"{API_URL}/repos/{repo}/security-advisories",
                params={"per_page": per_page, "sort": "published", "direction": "desc"},
            )
            if resp.status_code in (404, 403):
                return []
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitHub repo security advisories error: {e}"}]

    results = []
    for adv in data if isinstance(data, list) else []:
        results.append({
            "ghsa_id": adv.get("ghsa_id", ""),
            "cve_id": adv.get("cve_id", ""),
            "summary": adv.get("summary", ""),
            "description": (adv.get("description") or "")[:500],
            "severity": adv.get("severity", ""),
            "state": adv.get("state", ""),
            "published": adv.get("published_at", ""),
            "url": adv.get("html_url", ""),
            "cvss_score": adv.get("cvss", {}).get("score") if adv.get("cvss") else None,
            "cwes": [c.get("cwe_id", "") for c in adv.get("cwes", [])],
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
