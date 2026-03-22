import httpx
from typing import Optional
from config import HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key
import os

API_URL = "https://gitlab.com/api/v4"
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN", "")


def _headers() -> dict:
    h = {"User-Agent": USER_AGENT}
    if GITLAB_TOKEN:
        h["PRIVATE-TOKEN"] = GITLAB_TOKEN
    return h


def _project_id(project: str) -> str:
    """URL-encode a project path for the GitLab API (e.g. 'owner/repo' -> 'owner%2Frepo')."""
    return project.replace("/", "%2F")


# --- GitLab Search (global) ---

async def search_issues(
    query: str,
    scope: str = "issues",
    state: Optional[str] = None,
    confidential: Optional[bool] = None,
    per_page: int = 20,
) -> list[dict]:
    """Global search across GitLab for issues or merge requests."""
    cache_key = make_key("gl_search", query=query, scope=scope, state=state)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    params = {"search": query, "scope": scope, "per_page": per_page}
    if state:
        params["state"] = state
    if confidential is not None:
        params["confidential"] = str(confidential).lower()

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(f"{API_URL}/search", params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitLab search error: {e}"}]

    results = []
    for item in data if isinstance(data, list) else []:
        results.append({
            "title": item.get("title", ""),
            "url": item.get("web_url", ""),
            "state": item.get("state", ""),
            "labels": item.get("labels", []),
            "created": item.get("created_at", ""),
            "updated": item.get("updated_at", ""),
            "author": item.get("author", {}).get("username", "") if item.get("author") else "",
            "description_excerpt": (item.get("description") or "")[:500],
            "references": item.get("references", {}).get("full", "") if item.get("references") else "",
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


# --- Project Issues ---

async def search_project_issues(
    project: str,
    labels: Optional[list[str]] = None,
    search: Optional[str] = None,
    state: str = "all",
    per_page: int = 20,
) -> list[dict]:
    """Search issues in a specific GitLab project, optionally filtered by labels."""
    pid = _project_id(project)
    cache_key = make_key("gl_proj_issues", project=project, labels=labels, search=search, state=state)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    params = {"state": state, "per_page": per_page, "order_by": "created_at", "sort": "desc"}
    if labels:
        params["labels"] = ",".join(labels)
    if search:
        params["search"] = search

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(f"{API_URL}/projects/{pid}/issues", params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitLab project issues error: {e}"}]

    results = []
    for item in data if isinstance(data, list) else []:
        results.append({
            "title": item.get("title", ""),
            "url": item.get("web_url", ""),
            "state": item.get("state", ""),
            "labels": item.get("labels", []),
            "created": item.get("created_at", ""),
            "updated": item.get("updated_at", ""),
            "closed": item.get("closed_at"),
            "author": item.get("author", {}).get("username", "") if item.get("author") else "",
            "upvotes": item.get("upvotes", 0),
            "downvotes": item.get("downvotes", 0),
            "description_excerpt": (item.get("description") or "")[:500],
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


# --- Project Merge Requests ---

async def search_project_merge_requests(
    project: str,
    labels: Optional[list[str]] = None,
    search: Optional[str] = None,
    state: str = "all",
    per_page: int = 20,
) -> list[dict]:
    """Search merge requests in a specific GitLab project."""
    pid = _project_id(project)
    cache_key = make_key("gl_proj_mrs", project=project, labels=labels, search=search, state=state)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    params = {"state": state, "per_page": per_page, "order_by": "created_at", "sort": "desc"}
    if labels:
        params["labels"] = ",".join(labels)
    if search:
        params["search"] = search

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(f"{API_URL}/projects/{pid}/merge_requests", params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitLab MR search error: {e}"}]

    results = []
    for item in data if isinstance(data, list) else []:
        results.append({
            "title": item.get("title", ""),
            "url": item.get("web_url", ""),
            "state": item.get("state", ""),
            "labels": item.get("labels", []),
            "source_branch": item.get("source_branch", ""),
            "target_branch": item.get("target_branch", ""),
            "created": item.get("created_at", ""),
            "updated": item.get("updated_at", ""),
            "merged": item.get("merged_at"),
            "author": item.get("author", {}).get("username", "") if item.get("author") else "",
            "description_excerpt": (item.get("description") or "")[:500],
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


# --- Project Commits ---

async def search_project_commits(
    project: str,
    search: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    per_page: int = 20,
) -> list[dict]:
    """List commits from a GitLab project, optionally filtered by date."""
    pid = _project_id(project)
    cache_key = make_key("gl_proj_commits", project=project, search=search, since=since)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    params = {"per_page": per_page}
    if since:
        params["since"] = since
    if until:
        params["until"] = until

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(f"{API_URL}/projects/{pid}/repository/commits", params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"GitLab commits error: {e}"}]

    all_commits = data if isinstance(data, list) else []

    # Filter by search keyword in commit message if provided
    if search:
        kw = search.lower()
        all_commits = [c for c in all_commits if kw in (c.get("message") or "").lower()]

    results = []
    for item in all_commits:
        results.append({
            "sha": item.get("short_id", item.get("id", "")[:8]),
            "title": item.get("title", ""),
            "message": (item.get("message") or "")[:300],
            "url": item.get("web_url", ""),
            "author": item.get("author_name", ""),
            "date": item.get("committed_date", item.get("created_at", "")),
        })

    await cache_set(cache_key, results, ttl=1800)
    return results


# --- Convenience: Security signals in a project ---

async def search_security_signals(
    project: str,
    keyword: Optional[str] = None,
) -> dict:
    """Search a GitLab project for security-related issues, MRs, and commits.

    Tries common security labels and keyword patterns.
    """
    import asyncio

    security_labels = ["security", "vulnerability", "bug::vulnerability", "security-fix"]
    search_term = keyword or "security vulnerability CVE"

    issues_label, issues_search, mrs_label, mrs_search, commits = await asyncio.gather(
        search_project_issues(project, labels=security_labels[:2], per_page=15),
        search_project_issues(project, search=search_term, per_page=15),
        search_project_merge_requests(project, labels=security_labels[:2], per_page=10),
        search_project_merge_requests(project, search=search_term, per_page=10),
        search_project_commits(project, search=search_term, per_page=10),
        return_exceptions=True,
    )

    def safe(val):
        if isinstance(val, Exception):
            return []
        return [r for r in val if not isinstance(r, dict) or "error" not in r]

    # Merge and deduplicate issues
    seen_urls = set()
    all_issues = []
    for issue in safe(issues_label) + safe(issues_search):
        url = issue.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            all_issues.append(issue)

    seen_urls.clear()
    all_mrs = []
    for mr in safe(mrs_label) + safe(mrs_search):
        url = mr.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            all_mrs.append(mr)

    return {
        "project": project,
        "keyword": keyword,
        "issues": all_issues,
        "merge_requests": all_mrs,
        "commits": safe(commits),
    }
