import asyncio
import httpx
from typing import Optional
from mcp.server.fastmcp import FastMCP
from config import HTTP_TIMEOUT, USER_AGENT

from connectors import (
    nvd, osv, epss, kev, github, gitlab, hackyx, shodan,
    searchsploit, vulners, poc_in_github, nuclei_api, hacktricks,
)

mcp = FastMCP(
    "mcp-cve",
    instructions=(
        "Security Research Engine - A vulnerability intelligence tool for security researchers and pentesters. "
        "Search CVEs, exploits, attack surfaces, writeups, and recon data for any software or technology. "
        "Designed to help with penetration testing, R&D, and security research."
    ),
    host="0.0.0.0",
    port=8000,
)


def _safe(val, default=None):
    return default if isinstance(val, Exception) else val


def _clean_list(lst):
    if not lst or not isinstance(lst, list):
        return []
    return [r for r in lst if not isinstance(r, dict) or "error" not in r]


async def _fetch_poc_content(url: str) -> str:
    """Fetch raw content of a PoC URL. Converts GitHub blob URLs to raw format. Capped at 5000 chars."""
    raw_url = url
    if "github.com" in url and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
            resp = await client.get(raw_url, follow_redirects=True)
            if resp.status_code == 200:
                return resp.text[:5000]
    except Exception:
        pass
    return ""


async def _enrich_pocs_with_content(pocs: list) -> list:
    """Fetch raw content for each PoC entry that has a 'url' field."""
    async def _enrich(poc: dict) -> dict:
        url = poc.get("url", "")
        if url:
            poc = {**poc, "content": await _fetch_poc_content(url)}
        return poc

    return list(await asyncio.gather(*[_enrich(p) for p in pocs]))


# ---------------------------------------------------------------------------
# 1. get_technology_profile
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_technology_profile(name: str) -> dict:
    """
    Get a complete identity card of a technology: description, language, license, popularity,
    known CVE count, Shodan exposure stats, default ports, dorks, and more.
    Use this as a first step when researching a new target.

    Args:
        name: Name of the software, framework, or service (e.g. "Liferay", "Apache Tomcat", "GitLab").
    """
    (
        nvd_results, kev_results, gh_repos, shodan_data,
        hackyx_data, hacktricks_data, vulners_data,
    ) = await asyncio.gather(
        nvd.search_cves(keyword=name, results_per_page=5),
        kev.search_kev(name, limit=5),
        github.search_poc_repos(name, per_page=3),
        shodan.count(f'product:"{name}"'),
        hackyx.search_articles(query=name, per_page=3),
        hacktricks.search(name, per_page=5),
        vulners.search(f"{name} bulletinFamily:exploit", limit=5),
        return_exceptions=True,
    )

    nvd_results = _safe(nvd_results, [])
    kev_results = _safe(kev_results, [])
    gh_repos = _safe(gh_repos, [])
    shodan_data = _safe(shodan_data, {})
    hackyx_data = _safe(hackyx_data, {})
    hacktricks_data = _safe(hacktricks_data, [])
    vulners_data = _safe(vulners_data, {})

    severity_hint = {}
    for cve in _clean_list(nvd_results):
        sev = cve.get("cvss", {}).get("severity", "UNKNOWN")
        severity_hint[sev] = severity_hint.get(sev, 0) + 1

    repo_info = None
    for r in _clean_list(gh_repos):
        if name.lower() in r.get("name", "").lower():
            repo_info = r
            break

    return {
        "name": name,
        "note": "Use this profile as context. The LLM should enrich with its own knowledge about the technology (description, language, stack, default ports, admin paths, common dorks, default credentials).",
        "nvd_sample": {
            "recent_cves": [
                {"cve_id": c.get("cve_id"), "description": c.get("description", "")[:150], "cvss": c.get("cvss", {}).get("score")}
                for c in _clean_list(nvd_results)[:5]
            ],
            "severity_distribution": severity_hint,
        },
        "kev_entries": [
            {"cve_id": k.get("cve_id"), "name": k.get("name"), "date_added": k.get("date_added")}
            for k in kev_results[:5]
        ],
        "shodan": {
            "total_exposed": shodan_data.get("total", 0) if isinstance(shodan_data, dict) else 0,
            "facets": shodan_data.get("facets", {}) if isinstance(shodan_data, dict) else {},
            "dork": f'product:"{name}"',
        },
        "github_repo": repo_info,
        "hacktricks_pages": _clean_list(hacktricks_data)[:5],
        "hackyx_articles": hackyx_data.get("articles", [])[:3] if isinstance(hackyx_data, dict) else [],
        "vulners_exploits": vulners_data.get("results", [])[:5] if isinstance(vulners_data, dict) else [],
    }


# ---------------------------------------------------------------------------
# 2. search_vulns
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_vulns(
    software: str,
    version: Optional[str] = None,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    year: Optional[str] = None,
    has_exploit: bool = False,
    limit: int = 20,
) -> dict:
    """
    Search vulnerabilities for a given software/framework/service.
    Returns CVEs sorted by real-world exploitability (KEV > EPSS > CVSS).

    Args:
        software: Name of the software (e.g. "Apache Tomcat", "Liferay", "WordPress").
        version: Specific version or range to filter (e.g. "9.0", "< 16.0").
        severity: Filter by severity: CRITICAL, HIGH, MEDIUM, LOW.
        vuln_type: Filter by vulnerability class (e.g. "RCE", "SQLi", "SSRF", "deserialization", "XSS", "auth bypass").
        year: Filter by year (e.g. "2024").
        has_exploit: If true, only return CVEs with known public exploits.
        limit: Max number of results (default 20).
    """
    keyword = software
    if version:
        keyword += f" {version}"
    if vuln_type:
        keyword += f" {vuln_type}"

    # Search NVD + Nuclei (has_poc flag) in parallel
    nvd_task = nvd.search_cves(keyword=keyword, severity=severity, results_per_page=min(limit * 2, 50))
    nuclei_task = nuclei_api.search_cves(keyword=software, severity=severity.lower() if severity else None, limit=limit)

    nvd_results, nuclei_data = await asyncio.gather(nvd_task, nuclei_task, return_exceptions=True)

    nvd_results = _safe(nvd_results, [])
    nuclei_data = _safe(nuclei_data, {})

    if not nvd_results or (nvd_results and isinstance(nvd_results[0], dict) and "error" in nvd_results[0]):
        nvd_results = []

    # Filter by year
    if year:
        nvd_results = [c for c in nvd_results if c.get("published", "").startswith(year)]

    # Build set of CVEs with nuclei templates or PoCs
    nuclei_pocs = set()
    nuclei_templates_set = set()
    for nc in nuclei_data.get("cves", []) if isinstance(nuclei_data, dict) else []:
        cid = nc.get("cve_id", "")
        if nc.get("is_poc"):
            nuclei_pocs.add(cid)
        if nc.get("is_template"):
            nuclei_templates_set.add(cid)

    # Enrich with EPSS (batch)
    cve_ids = [c["cve_id"] for c in nvd_results if c.get("cve_id")]
    epss_data = {}
    if cve_ids:
        epss_results = _safe(await epss.get_epss_batch(cve_ids), [])
        if epss_results and not (isinstance(epss_results[0], dict) and "error" in epss_results[0]):
            epss_data = {e["cve"]: e for e in epss_results}

    # Enrich with KEV
    kev_checks = await asyncio.gather(*[kev.is_in_kev(cid) for cid in cve_ids])
    kev_set = {cid for cid, in_kev in zip(cve_ids, kev_checks) if in_kev}

    # Build enriched results
    enriched = []
    for cve in nvd_results:
        if "error" in cve:
            continue
        cve_id = cve.get("cve_id", "")
        epss_info = epss_data.get(cve_id, {})
        has_exploit_refs = len(cve.get("exploit_references", [])) > 0
        in_kev = cve_id in kev_set
        has_nuclei_poc = cve_id in nuclei_pocs
        has_nuclei_tpl = cve_id in nuclei_templates_set

        if has_exploit and not (has_exploit_refs or in_kev or has_nuclei_poc):
            continue

        enriched.append({
            "cve_id": cve_id,
            "description": cve.get("description", ""),
            "published": cve.get("published", ""),
            "cvss": cve.get("cvss", {}),
            "cwes": cve.get("cwes", []),
            "epss": {"score": epss_info.get("score"), "percentile": epss_info.get("percentile")},
            "in_kev": in_kev,
            "has_exploit_refs": has_exploit_refs,
            "has_nuclei_poc": has_nuclei_poc,
            "has_nuclei_template": has_nuclei_tpl,
            "affected": cve.get("affected", [])[:5],
            "nvd_url": cve.get("nvd_url", ""),
        })

    # Sort: KEV first, then EPSS desc, then CVSS desc
    enriched.sort(key=lambda x: (
        not x.get("in_kev", False),
        not x.get("has_nuclei_poc", False),
        -(x.get("epss", {}).get("score") or 0),
        -(x.get("cvss", {}).get("score") or 0),
    ))

    return {
        "software": software,
        "version_filter": version,
        "total_found": len(enriched),
        "vulnerabilities": enriched[:limit],
    }


# ---------------------------------------------------------------------------
# 3. get_cve_details
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_cve_details(
    cve_id: str,
    limit: int = 5,
    include_poc_content: bool = False,
) -> dict:
    """
    Get complete details of a specific CVE: description, scores, affected versions,
    public exploits from all sources (Exploit-DB, SearchSploit, Metasploit, Nuclei,
    GitHub PoC, PoC-in-GitHub, Vulners), KEV status, EPSS, writeups, and fix commits.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-1234").
        limit: Max results per exploit source (default 5). Increase for deeper research.
        include_poc_content: If true, fetch and include raw content of each PoC URL (default false).
    """
    per = max(1, min(limit, 20))

    (
        nvd_data, epss_data, kev_entry,
        poc_repos, poc_aggregated,
        ssploit_results,
        nuclei_gh, nuclei_cve, msf_results,
        vulners_data, hackyx_results, gh_commits,
    ) = await asyncio.gather(
        nvd.get_cve(cve_id),
        epss.get_epss(cve_id),
        kev.get_kev_entry(cve_id),
        github.search_poc_repos(cve_id, per_page=per),
        poc_in_github.search_poc(cve_id),
        searchsploit.search_by_cve(cve_id),
        github.search_nuclei_templates(cve_id),
        nuclei_api.search_cves(keyword=cve_id, limit=per),
        github.search_metasploit_modules(cve_id),
        vulners.search_by_cve(cve_id, limit=per),
        hackyx.search_articles(query=cve_id, per_page=per),
        github.search_security_commits(cve_id, per_page=per),
        return_exceptions=True,
    )

    nvd_data = _safe(nvd_data, {})
    epss_data = _safe(epss_data, {})
    kev_entry = _safe(kev_entry)
    poc_repos = _clean_list(_safe(poc_repos, []))
    poc_aggregated = _clean_list(_safe(poc_aggregated, []))
    ssploit_results = _clean_list(_safe(ssploit_results, []))
    nuclei_gh = _clean_list(_safe(nuclei_gh, []))
    nuclei_cve_data = _safe(nuclei_cve, {})
    msf_results = _clean_list(_safe(msf_results, []))
    vulners_data = _safe(vulners_data, {})
    hackyx_results = _safe(hackyx_results, {})
    gh_commits = _clean_list(_safe(gh_commits, []))

    # Merge PoC sources (deduplicate by URL)
    seen_urls = set()
    all_pocs = []
    for poc in poc_aggregated + poc_repos:
        url = poc.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            all_pocs.append(poc)

    # Nuclei data from ProjectDiscovery API
    nuclei_api_data = []
    for nc in nuclei_cve_data.get("cves", []) if isinstance(nuclei_cve_data, dict) else []:
        if nc.get("is_template") or nc.get("is_poc"):
            nuclei_api_data.append({
                "is_template": nc.get("is_template"),
                "is_poc": nc.get("is_poc"),
                "poc_urls": nc.get("poc_urls", []),
                "template_url": nc.get("nuclei_template_url", ""),
            })

    all_edb = ssploit_results

    total_exploits = len(all_pocs) + len(all_edb) + len(nuclei_gh) + len(msf_results) + len(nuclei_api_data)

    github_pocs_out = all_pocs[:per]
    if include_poc_content:
        github_pocs_out = await _enrich_pocs_with_content(github_pocs_out)

    # Truncate NVD references (deduplicate by URL)
    raw_refs = (nvd_data or {}).get("references", [])
    seen_ref_urls = set()
    refs = []
    for r in raw_refs:
        u = r.get("url", "")
        if u not in seen_ref_urls:
            seen_ref_urls.add(u)
            refs.append(r)
    refs = refs[:20]

    return {
        "cve_id": cve_id,
        "limit_per_source": per,
        "nvd": nvd_data or {"error": "CVE not found in NVD"},
        "epss": epss_data,
        "kev": kev_entry,
        "exploits": {
            "total_exploits_found": total_exploits,
            "github_poc": github_pocs_out,
            "exploit_db_and_searchsploit": all_edb[:per],
            "nuclei_templates_github": nuclei_gh[:per],
            "nuclei_projectdiscovery": nuclei_api_data[:per],
            "metasploit_modules": msf_results[:per],
            "vulners": (vulners_data.get("results", []) if isinstance(vulners_data, dict) else [])[:per],
        },
        "writeups": (hackyx_results.get("articles", []) if isinstance(hackyx_results, dict) else [])[:per],
        "fix_commits": gh_commits[:per],
        "references": refs,
        "references_total": len(seen_ref_urls),
    }


# ---------------------------------------------------------------------------
# 4. search_exploits
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_exploits(
    cve_id: Optional[str] = None,
    software: Optional[str] = None,
    exploit_type: Optional[str] = None,
    limit: int = 10,
    include_poc_content: bool = False,
) -> dict:
    """
    Search for public exploits and PoCs across all sources: GitHub repos, PoC-in-GitHub,
    SearchSploit, Metasploit modules, Nuclei templates, and Vulners.

    Args:
        cve_id: CVE identifier to search exploits for (e.g. "CVE-2024-1234").
        software: Software name to search exploits for (e.g. "Apache Struts").
        exploit_type: Filter by type: "poc", "metasploit", "nuclei", "searchsploit", "vulners", or None for all.
        limit: Max results per source (default 10).
        include_poc_content: If true, fetch and include raw content of each PoC URL (default false).
    """
    query = cve_id or software
    if not query:
        return {"error": "Provide either cve_id or software parameter"}

    per = max(1, min(limit, 50))
    tasks = {}

    if exploit_type in (None, "poc"):
        tasks["github_poc"] = github.search_poc_repos(f"{query} exploit OR poc OR vulnerability", per_page=per)
        if cve_id:
            tasks["poc_in_github"] = poc_in_github.search_poc(cve_id)

    if exploit_type in (None, "searchsploit"):
        tasks["searchsploit"] = searchsploit.search(query, limit=per)

    if exploit_type in (None, "nuclei"):
        tasks["nuclei_github"] = github.search_nuclei_templates(query)
        tasks["nuclei_api"] = nuclei_api.search_pocs(query, limit=per)

    if exploit_type in (None, "metasploit"):
        tasks["metasploit_modules"] = github.search_metasploit_modules(query)

    if exploit_type in (None, "vulners"):
        tasks["vulners"] = vulners.search_exploits(query, limit=per)

    results_raw = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results = {}
    for key, val in zip(tasks.keys(), results_raw):
        val = _safe(val, [])
        if isinstance(val, dict):
            results[key] = (val.get("results", []) if "results" in val else val.get("cves", []) if "cves" in val else [val])[:per]
        elif isinstance(val, list):
            results[key] = _clean_list(val)[:per]
        else:
            results[key] = []

    # Enrich PoC repos with content if requested
    if include_poc_content:
        if "github_poc" in results:
            results["github_poc"] = await _enrich_pocs_with_content(results["github_poc"])
        if "poc_in_github" in results:
            results["poc_in_github"] = await _enrich_pocs_with_content(results["poc_in_github"])

    total = sum(len(v) for v in results.values())

    return {
        "query": query,
        "limit_per_source": per,
        "total_found": total,
        **results,
    }


# ---------------------------------------------------------------------------
# 5. get_attack_surface
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_attack_surface(software: str) -> dict:
    """
    Analyze the known attack surface of a technology: recurring vulnerability classes,
    historical CVE distribution by CWE, KEV entries, and exploit availability.
    Helps understand where to focus during a pentest.

    Args:
        software: Name of the software (e.g. "Confluence", "Liferay", "Jenkins").
    """
    nvd_task = nvd.search_cves(keyword=software, results_per_page=50)
    kev_task = kev.search_kev(software, limit=20)
    hackyx_task = hackyx.search_articles(query=f"{software} vulnerability exploit", per_page=5)
    hacktricks_task = hacktricks.search(software, per_page=10)

    nvd_results, kev_results, hackyx_data, ht_results = await asyncio.gather(
        nvd_task, kev_task, hackyx_task, hacktricks_task,
        return_exceptions=True,
    )

    nvd_results = _clean_list(_safe(nvd_results, []))
    kev_results = _safe(kev_results, [])
    hackyx_data = _safe(hackyx_data, {})
    ht_results = _clean_list(_safe(ht_results, []))

    cwe_counts = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    yearly_counts = {}
    exploit_available = 0

    for cve in nvd_results:
        for cwe_id in cve.get("cwes", []):
            cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1
        sev = cve.get("cvss", {}).get("severity", "")
        if sev in severity_counts:
            severity_counts[sev] += 1
        pub = cve.get("published", "")[:4]
        if pub:
            yearly_counts[pub] = yearly_counts.get(pub, 0) + 1
        if cve.get("exploit_references"):
            exploit_available += 1

    top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "software": software,
        "total_cves_analyzed": len(nvd_results),
        "severity_distribution": severity_counts,
        "top_cwes": [{"cwe": cwe, "count": count} for cwe, count in top_cwes],
        "yearly_distribution": dict(sorted(yearly_counts.items(), reverse=True)),
        "cves_with_exploits": exploit_available,
        "kev_entries": [
            {"cve_id": k.get("cve_id"), "name": k.get("name"), "date_added": k.get("date_added")}
            for k in kev_results
        ],
        "hacktricks_pages": ht_results[:10],
        "related_writeups": hackyx_data.get("articles", [])[:5] if isinstance(hackyx_data, dict) else [],
        "note": "The LLM should analyze the CWE distribution to identify recurring vulnerability patterns, common attack vectors, and recommend what to test during a pentest.",
    }


# ---------------------------------------------------------------------------
# 6. search_writeups
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_writeups(
    query: str,
    source: Optional[str] = None,
    page: int = 1,
    per_page: int = 10,
) -> dict:
    """
    Search for security writeups, blog posts, bug bounty reports, and technical analyses.
    Uses Hackyx search engine.

    Args:
        query: Search query - CVE ID, software name, or keywords (e.g. "Liferay RCE", "CVE-2024-1234").
        source: Filter by source (e.g. "hackerone", "medium", "github"). None for all.
        page: Page number (default 1).
        per_page: Results per page (default 10, max 50).
    """
    result = await hackyx.search_articles(
        query=query, source=source, page=page, per_page=min(per_page, 50),
    )

    if isinstance(result, list) and result and "error" in result[0]:
        return {"error": result[0]["error"]}

    return {
        "query": query,
        "source_filter": source,
        "total": result.get("total", 0) if isinstance(result, dict) else 0,
        "page": page,
        "articles": result.get("articles", []) if isinstance(result, dict) else [],
    }


# ---------------------------------------------------------------------------
# 7. search_github_security
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_github_security(
    target: str,
    keyword: Optional[str] = None,
    labels: Optional[str] = None,
    signal_type: Optional[str] = None,
    platform: Optional[str] = None,
) -> dict:
    """
    Search GitHub AND GitLab for security-related signals: issues, pull requests /
    merge requests, commits, and advisories. Supports both platforms.

    Args:
        target: Repository (e.g. "liferay/liferay-portal") or software name (e.g. "Tomcat").
        keyword: Additional keyword filter (e.g. "RCE", "deserialization", specific CVE).
        labels: Comma-separated labels to filter issues (e.g. "security,vulnerability,CVE").
        signal_type: Filter by type: "issue", "pr", "commit", "advisory", or None for all.
        platform: "github", "gitlab", or None for both. Auto-detected from target when possible (e.g. gitlab.com URLs).
    """
    query = target
    if keyword:
        query += f" {keyword}"

    label_list = [l.strip() for l in labels.split(",")] if labels else None

    # Auto-detect platform from target
    is_gitlab = platform == "gitlab" or "gitlab.com" in target or "gitlab" in target.lower()
    is_github = platform == "github" or (not is_gitlab and platform is None)

    # Clean target for GitLab (remove gitlab.com/ prefix if present)
    gl_target = target
    if "gitlab.com/" in gl_target:
        gl_target = gl_target.split("gitlab.com/", 1)[1].rstrip("/")

    tasks = {}

    # --- GitHub ---
    if is_github or platform is None:
        if signal_type in (None, "issue", "pr"):
            tasks["github_issues_prs"] = github.search_security_issues(query, labels=label_list)
        if signal_type in (None, "commit"):
            tasks["github_commits"] = github.search_security_commits(query)
        if signal_type in (None, "advisory"):
            tasks["github_advisories"] = github.search_advisories(keyword=query)
        # Label-based search + repo Security tab for specific repos
        if "/" in target and not is_gitlab:
            if signal_type in (None, "issue"):
                sec_labels = label_list or ["security", "vulnerability"]
                tasks["github_labeled_issues"] = github.search_issues_by_label(target, sec_labels, per_page=15)
            if signal_type in (None, "advisory"):
                tasks["github_repo_security"] = github.search_repo_security_advisories(target, per_page=10)

    # --- GitLab ---
    if is_gitlab or platform is None:
        if "/" in gl_target:
            # Specific GitLab project
            tasks["gitlab_security"] = gitlab.search_security_signals(gl_target, keyword=keyword)
        else:
            # Global GitLab search
            if signal_type in (None, "issue"):
                tasks["gitlab_issues"] = gitlab.search_issues(f"{query} security vulnerability", scope="issues")
            if signal_type in (None, "pr"):
                tasks["gitlab_merge_requests"] = gitlab.search_issues(f"{query} security vulnerability", scope="merge_requests")

    results_raw = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results = {}
    for key, val in zip(tasks.keys(), results_raw):
        val = _safe(val, [])
        if isinstance(val, dict):
            results[key] = val
        else:
            results[key] = _clean_list(val)

    return {"target": target, "keyword": keyword, "labels": labels, "platform": platform, **results}


# ---------------------------------------------------------------------------
# 8. search_package_vulns
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_package_vulns(
    ecosystem: str,
    package_name: str,
    version: Optional[str] = None,
    limit: int = 20,
    page: int = 1,
) -> dict:
    """
    Search vulnerabilities for a specific open source package using OSV and GitHub Advisory databases.

    Args:
        ecosystem: Package ecosystem - "npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "NuGet", "Packagist".
        package_name: Name of the package (e.g. "lodash", "django", "log4j").
        version: Specific version to check (e.g. "2.14.1"). If omitted, returns all known vulns.
        limit: Max results per source per page (default 20).
        page: Page number for pagination (default 1).
    """
    osv_results, ghsa_results = await asyncio.gather(
        osv.query_package(ecosystem=ecosystem, package_name=package_name, version=version),
        github.search_advisories(keyword=package_name, ecosystem=ecosystem.lower()),
        return_exceptions=True,
    )

    per = max(1, min(limit, 100))
    offset = (max(1, page) - 1) * per

    osv_clean = _clean_list(_safe(osv_results, []))
    ghsa_clean = _clean_list(_safe(ghsa_results, []))

    return {
        "ecosystem": ecosystem,
        "package": package_name,
        "version": version,
        "page": page,
        "limit": per,
        "total_found": len(osv_clean) + len(ghsa_clean),
        "osv_vulnerabilities": osv_clean[offset:offset + per],
        "osv_total": len(osv_clean),
        "github_advisories": ghsa_clean[offset:offset + per],
        "github_advisories_total": len(ghsa_clean),
    }


# ---------------------------------------------------------------------------
# 9. get_recon_data
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_recon_data(query: str) -> dict:
    """
    Get passive reconnaissance data: Shodan exposure stats, number of instances
    exposed on the internet, top countries, versions, and ready-to-use dorks.

    Args:
        query: Shodan search query or software name (e.g. "Apache Tomcat", 'http.title:"Liferay"').
    """
    dorks = {
        "shodan": [f'product:"{query}"', f'http.title:"{query}"', f'http.html:"{query}"'],
        "censys": [f'services.software.product:"{query}"', f'services.http.response.html_title:"{query}"'],
        "google": [
            f'intitle:"{query}" inurl:admin',
            f'intitle:"{query}" inurl:login',
            f'"{query}" filetype:conf OR filetype:xml OR filetype:properties',
        ],
        "fofa": [f'app="{query}"', f'title="{query}"'],
    }

    shodan_stats, shodan_title = await asyncio.gather(
        shodan.count(f'product:"{query}"'),
        shodan.count(f'http.title:"{query}"'),
    )

    return {
        "query": query,
        "shodan": {"by_product": shodan_stats, "by_title": shodan_title},
        "dorks": dorks,
        "note": "Use these dorks directly in each search engine. Shodan stats require SHODAN_API_KEY to be set.",
    }


# ---------------------------------------------------------------------------
# 10. get_default_credentials
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_default_credentials(software: str) -> dict:
    """
    Search for known default credentials, common misconfigurations, and default
    admin paths for a given software.

    Args:
        software: Name of the software (e.g. "Jenkins", "Tomcat", "Grafana").
    """
    creds_results, hackyx_results = await asyncio.gather(
        github.search_default_creds(software),
        hackyx.search_articles(query=f"{software} default credentials OR misconfiguration", per_page=5),
        return_exceptions=True,
    )

    return {
        "software": software,
        "defaultcreds_cheatsheet": _clean_list(_safe(creds_results, [])),
        "related_articles": (_safe(hackyx_results, {})).get("articles", [])[:5] if isinstance(_safe(hackyx_results, {}), dict) else [],
        "note": "The LLM should supplement with its knowledge of default credentials, admin paths, debug endpoints, and dangerous default configs for this software.",
    }


# ---------------------------------------------------------------------------
# 11. compare_technologies
# ---------------------------------------------------------------------------

@mcp.tool()
async def compare_technologies(software_a: str, software_b: str) -> dict:
    """
    Compare the security posture of two technologies side by side:
    CVE count, severity distribution, KEV entries, exploit availability.

    Args:
        software_a: First software to compare (e.g. "Confluence").
        software_b: Second software to compare (e.g. "Jira").
    """
    nvd_a, nvd_b, kev_a, kev_b, shodan_a, shodan_b = await asyncio.gather(
        nvd.search_cves(keyword=software_a, results_per_page=40),
        nvd.search_cves(keyword=software_b, results_per_page=40),
        kev.search_kev(software_a, limit=50),
        kev.search_kev(software_b, limit=50),
        shodan.count(f'product:"{software_a}"'),
        shodan.count(f'product:"{software_b}"'),
        return_exceptions=True,
    )

    def analyze(cves):
        cves = _clean_list(cves)
        severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cwes = {}
        exploit_count = 0
        for c in cves:
            sev = c.get("cvss", {}).get("severity", "")
            if sev in severity:
                severity[sev] += 1
            for cwe in c.get("cwes", []):
                cwes[cwe] = cwes.get(cwe, 0) + 1
            if c.get("exploit_references"):
                exploit_count += 1
        top_cwes = sorted(cwes.items(), key=lambda x: x[1], reverse=True)[:5]
        return {"total_cves": len(cves), "severity": severity, "top_cwes": [{"cwe": k, "count": v} for k, v in top_cwes], "with_exploits": exploit_count}

    return {
        software_a: {
            "cve_analysis": analyze(_safe(nvd_a, [])),
            "kev_count": len(_safe(kev_a, [])),
            "shodan_exposed": _safe(shodan_a, {}).get("total", 0) if isinstance(_safe(shodan_a, {}), dict) else 0,
        },
        software_b: {
            "cve_analysis": analyze(_safe(nvd_b, [])),
            "kev_count": len(_safe(kev_b, [])),
            "shodan_exposed": _safe(shodan_b, {}).get("total", 0) if isinstance(_safe(shodan_b, {}), dict) else 0,
        },
    }


# ---------------------------------------------------------------------------
# 12. get_vuln_timeline
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_vuln_timeline(cve_id: str) -> dict:
    """
    Get the complete timeline of a vulnerability: publication, patch, exploit release,
    KEV addition. Helps understand how fast a vuln went from disclosure to exploitation.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-1234").
    """
    nvd_data, kev_entry, epss_data, nuclei_data = await asyncio.gather(
        nvd.get_cve(cve_id),
        kev.get_kev_entry(cve_id),
        epss.get_epss(cve_id),
        nuclei_api.search_cves(keyword=cve_id, limit=1),
        return_exceptions=True,
    )

    nvd_data = _safe(nvd_data, {})
    kev_entry = _safe(kev_entry)
    epss_data = _safe(epss_data, {})
    nuclei_data = _safe(nuclei_data, {})

    timeline = []
    if nvd_data:
        if nvd_data.get("published"):
            timeline.append({"event": "CVE Published", "date": nvd_data["published"], "source": "NVD"})
        if nvd_data.get("modified"):
            timeline.append({"event": "CVE Last Modified", "date": nvd_data["modified"], "source": "NVD"})
    if kev_entry:
        timeline.append({"event": "Added to CISA KEV (actively exploited)", "date": kev_entry.get("date_added", ""), "source": "CISA KEV"})

    timeline.sort(key=lambda x: x.get("date", ""))

    return {
        "cve_id": cve_id,
        "timeline": timeline,
        "epss_current": epss_data,
        "kev_details": kev_entry,
        "nuclei_status": nuclei_data.get("cves", [{}])[0] if isinstance(nuclei_data, dict) and nuclei_data.get("cves") else None,
        "nvd_references": (nvd_data or {}).get("references", []),
    }


# ---------------------------------------------------------------------------
# 13. search_by_cwe
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_by_cwe(
    cwe_id: Optional[str] = None,
    vuln_class: Optional[str] = None,
    software: Optional[str] = None,
    limit: int = 20,
) -> dict:
    """
    Search vulnerabilities by weakness class (CWE). Useful to find all instances
    of a specific vulnerability type (e.g. all deserialization bugs, all SSRF, etc.).

    Args:
        cwe_id: CWE identifier (e.g. "CWE-502" for deserialization, "CWE-918" for SSRF).
        vuln_class: Common name - "deserialization", "sqli", "ssrf", "xss", "rce", "xxe", "path_traversal", "ssti", "auth_bypass", "idor".
        software: Optional software filter (e.g. "Liferay").
        limit: Max results (default 20).
    """
    CWE_MAP = {
        "deserialization": "CWE-502", "sqli": "CWE-89", "sql_injection": "CWE-89",
        "ssrf": "CWE-918", "xss": "CWE-79", "cross_site_scripting": "CWE-79",
        "rce": "CWE-94", "code_injection": "CWE-94", "command_injection": "CWE-78",
        "xxe": "CWE-611", "path_traversal": "CWE-22", "directory_traversal": "CWE-22",
        "ssti": "CWE-1336", "template_injection": "CWE-1336",
        "auth_bypass": "CWE-287", "authentication_bypass": "CWE-287",
        "idor": "CWE-639", "file_upload": "CWE-434", "open_redirect": "CWE-601",
        "csrf": "CWE-352", "buffer_overflow": "CWE-120", "use_after_free": "CWE-416",
        "integer_overflow": "CWE-190", "race_condition": "CWE-362", "jndi": "CWE-917",
    }

    resolved_cwe = cwe_id
    if not resolved_cwe and vuln_class:
        resolved_cwe = CWE_MAP.get(vuln_class.lower().replace(" ", "_"))

    if not resolved_cwe:
        return {"error": "Provide either cwe_id or a recognized vuln_class", "supported_classes": list(CWE_MAP.keys())}

    nvd_results = await nvd.search_cves(
        keyword=software if software else None,
        cwe_id=resolved_cwe,
        results_per_page=min(limit, 50),
    )

    clean = _clean_list(nvd_results)

    return {
        "cwe_id": resolved_cwe,
        "vuln_class": vuln_class,
        "software_filter": software,
        "total_found": len(clean),
        "vulnerabilities": [
            {
                "cve_id": c.get("cve_id"),
                "description": c.get("description", "")[:200],
                "published": c.get("published"),
                "cvss": c.get("cvss", {}).get("score"),
                "severity": c.get("cvss", {}).get("severity"),
                "has_exploits": len(c.get("exploit_references", [])) > 0,
                "nvd_url": c.get("nvd_url"),
            }
            for c in clean[:limit]
        ],
    }


# ---------------------------------------------------------------------------
# 14. searchsploit (NEW)
# ---------------------------------------------------------------------------

@mcp.tool()
async def searchsploit_search(
    keyword: str,
    platform: Optional[str] = None,
    exploit_type: Optional[str] = None,
    limit: int = 25,
) -> dict:
    """
    Search the Exploit-DB database offline (equivalent to the searchsploit CLI tool).
    Searches through ~50,000 exploits, shellcodes, and papers from Exploit-DB.

    Args:
        keyword: Search keywords (e.g. "Apache Tomcat", "Liferay", "WordPress plugin").
        platform: Filter by platform (e.g. "linux", "windows", "php", "java", "python", "multiple").
        exploit_type: Filter by type (e.g. "local", "remote", "webapps", "dos").
        limit: Max results (default 25).
    """
    results = await searchsploit.search(
        keyword=keyword, platform=platform, exploit_type=exploit_type, limit=limit,
    )

    return {
        "keyword": keyword,
        "platform": platform,
        "type": exploit_type,
        "total_found": len(_clean_list(results)),
        "exploits": _clean_list(results),
    }


# ---------------------------------------------------------------------------
# 15. get_security_resources (NEW)
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_security_resources(
    query: str,
    resource_type: Optional[str] = None,
    limit: int = 15,
) -> dict:
    """
    Get security resources for a technology: writeups, cheatsheets (HackTricks),
    articles, exploit databases entries, and research papers. Returns 10-15 actionable
    resources to help a researcher or pentester get started.

    Args:
        query: Software name, CVE, or topic (e.g. "Liferay", "Java deserialization", "SSRF").
        resource_type: Filter: "writeup", "cheatsheet", "exploit", "article", or None for all.
        limit: Max total results (default 15).
    """
    tasks = {}

    if resource_type in (None, "writeup", "article"):
        tasks["hackyx_writeups"] = hackyx.search_articles(query=query, per_page=min(limit, 10))
        tasks["vulners_articles"] = vulners.search(query, limit=min(limit, 10))

    if resource_type in (None, "cheatsheet"):
        tasks["hacktricks"] = hacktricks.search(query, per_page=min(limit, 10))

    if resource_type in (None, "exploit"):
        tasks["searchsploit"] = searchsploit.search(query, limit=min(limit, 10))
        tasks["vulners_exploits"] = vulners.search_exploits(query, limit=min(limit, 10))

    results_raw = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results = {}
    for key, val in zip(tasks.keys(), results_raw):
        val = _safe(val, [])
        if isinstance(val, dict):
            if "articles" in val:
                results[key] = val.get("articles", [])
            elif "results" in val:
                results[key] = val.get("results", [])
            else:
                results[key] = [val] if val else []
        elif isinstance(val, list):
            results[key] = _clean_list(val)
        else:
            results[key] = []

    total = sum(len(v) for v in results.values())

    return {
        "query": query,
        "resource_type": resource_type,
        "total_resources": total,
        **results,
    }


# ---------------------------------------------------------------------------
# 16. search_vulners (NEW)
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_vulners(
    query: str,
    limit: int = 20,
) -> dict:
    """
    Search the Vulners aggregated security database using Lucene query syntax.
    Vulners indexes exploits from Exploit-DB, PacketStorm, GitHub, Metasploit,
    and many other sources in one place.

    Query examples:
        - "Apache Tomcat RCE"
        - "title:*liferay* bulletinFamily:exploit"
        - "CVE-2024-1234"
        - "bulletinFamily:exploit published:[2024-01-01 TO 2024-12-31]"

    Args:
        query: Lucene-syntax search query.
        limit: Max results (default 20).
    """
    result = await vulners.search(query=query, limit=limit)
    if isinstance(result, dict) and "error" in result:
        return result

    return {
        "query": query,
        "total": result.get("total", 0) if isinstance(result, dict) else 0,
        "results": result.get("results", []) if isinstance(result, dict) else [],
    }


# ---------------------------------------------------------------------------
# 17. search_nuclei_pocs (NEW)
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_nuclei_pocs(
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
    only_with_poc: bool = True,
    only_with_template: bool = False,
    limit: int = 20,
    include_poc_content: bool = False,
) -> dict:
    """
    Search the ProjectDiscovery CVE database for vulnerabilities that have
    Nuclei templates or known PoCs. ProjectDiscovery tracks which CVEs have
    detection templates and public exploits.

    Args:
        keyword: Software or keyword to search (e.g. "Apache", "WordPress").
        cve_id: Specific CVE to look up.
        severity: Filter by severity: "critical", "high", "medium", "low".
        only_with_poc: Only return CVEs with known PoCs (default true).
        only_with_template: Only return CVEs with Nuclei templates.
        limit: Max results (default 20).
        include_poc_content: If true, fetch and include raw content of each PoC URL (default false).
    """
    search_term = cve_id or keyword
    if not search_term:
        return {"error": "Provide either keyword or cve_id"}

    result = await nuclei_api.search_cves(
        keyword=search_term,
        is_poc=True if only_with_poc else None,
        is_template=True if only_with_template else None,
        severity=severity,
        limit=limit,
    )

    if isinstance(result, dict) and "error" in result:
        return result

    cves = result.get("cves", []) if isinstance(result, dict) else []

    if include_poc_content:
        async def _enrich_cve(cve: dict) -> dict:
            poc_urls = cve.get("poc_urls", [])
            if poc_urls:
                contents = await asyncio.gather(*[_fetch_poc_content(u) for u in poc_urls])
                cve = {**cve, "poc_contents": [{"url": u, "content": c} for u, c in zip(poc_urls, contents)]}
            return cve
        cves = list(await asyncio.gather(*[_enrich_cve(c) for c in cves]))

    return {
        "query": search_term,
        "total": result.get("total", 0) if isinstance(result, dict) else 0,
        "cves": cves,
    }


# ---------------------------------------------------------------------------
# 18. search_advisories (NEW)
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_advisories(
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None,
    ecosystem: Optional[str] = None,
    severity: Optional[str] = None,
    advisory_type: Optional[str] = None,
    cwes: Optional[str] = None,
    include_unreviewed: bool = True,
    per_page: int = 20,
) -> dict:
    """
    Search the GitHub Advisory Database (GHSA). Can search reviewed (GitHub-verified),
    unreviewed (community/third-party), and malware advisories.

    This is the same database visible at https://github.com/advisories.

    Args:
        keyword: Search keyword (e.g. "Liferay", "log4j", "Spring").
        cve_id: Specific CVE identifier.
        ecosystem: Package ecosystem filter: "npm", "pip", "maven", "go", "nuget", "composer", "cargo", "rubygems".
        severity: Severity filter: "critical", "high", "medium", "low".
        advisory_type: "reviewed" (GitHub-verified), "unreviewed" (community), "malware", or None.
        cwes: Comma-separated CWE IDs to filter (e.g. "79,89,502").
        include_unreviewed: If true and no advisory_type specified, also search unreviewed advisories (default true).
        per_page: Results per page (default 20, max 100).
    """
    if advisory_type:
        # Single type search
        results = await github.search_advisories(
            keyword=keyword, cve_id=cve_id, ecosystem=ecosystem,
            severity=severity, advisory_type=advisory_type, cwes=cwes,
            per_page=per_page,
        )
        return {
            "keyword": keyword, "cve_id": cve_id, "type": advisory_type,
            "total": len(_clean_list(results)),
            "advisories": _clean_list(results),
        }

    if include_unreviewed:
        # Search both reviewed and unreviewed
        all_types = await github.search_advisories_all_types(
            keyword=keyword, ecosystem=ecosystem, severity=severity, per_page=per_page,
        )
        return {
            "keyword": keyword, "cve_id": cve_id,
            "reviewed": all_types.get("reviewed", []),
            "unreviewed": all_types.get("unreviewed", []),
            "malware": all_types.get("malware", []),
            "total_reviewed": len(all_types.get("reviewed", [])),
            "total_unreviewed": len(all_types.get("unreviewed", [])),
            "total_malware": len(all_types.get("malware", [])),
        }

    # Default: reviewed only
    results = await github.search_advisories(
        keyword=keyword, cve_id=cve_id, ecosystem=ecosystem,
        severity=severity, cwes=cwes, per_page=per_page,
    )
    return {
        "keyword": keyword, "cve_id": cve_id, "type": "reviewed",
        "total": len(_clean_list(results)),
        "advisories": _clean_list(results),
    }


# ---------------------------------------------------------------------------
# 19. search_gitlab_security (NEW)
# ---------------------------------------------------------------------------

@mcp.tool()
async def search_gitlab_security(
    project: str,
    keyword: Optional[str] = None,
    labels: Optional[str] = None,
    signal_type: Optional[str] = None,
) -> dict:
    """
    Search a GitLab project for security-related issues, merge requests, and commits.
    Automatically searches common security labels and keywords.

    Args:
        project: GitLab project path (e.g. "gitlab-org/gitlab", "liferay/liferay-portal").
        keyword: Additional keyword filter (e.g. "RCE", "CVE-2024-1234", "deserialization").
        labels: Comma-separated labels to search (e.g. "security,vulnerability"). Auto-detects if not set.
        signal_type: "issue", "mr", "commit", or None for all.
    """
    # Clean project path
    project_clean = project
    if "gitlab.com/" in project_clean:
        project_clean = project_clean.split("gitlab.com/", 1)[1].rstrip("/")

    label_list = [l.strip() for l in labels.split(",")] if labels else None
    search_term = keyword or "security vulnerability CVE"

    tasks = {}

    if signal_type in (None, "issue"):
        if label_list:
            tasks["issues_by_label"] = gitlab.search_project_issues(project_clean, labels=label_list, per_page=20)
        else:
            tasks["issues_by_label"] = gitlab.search_project_issues(project_clean, labels=["security", "vulnerability"], per_page=20)
        tasks["issues_by_search"] = gitlab.search_project_issues(project_clean, search=search_term, per_page=15)

    if signal_type in (None, "mr"):
        if label_list:
            tasks["mrs_by_label"] = gitlab.search_project_merge_requests(project_clean, labels=label_list, per_page=15)
        else:
            tasks["mrs_by_label"] = gitlab.search_project_merge_requests(project_clean, labels=["security"], per_page=15)
        tasks["mrs_by_search"] = gitlab.search_project_merge_requests(project_clean, search=search_term, per_page=10)

    if signal_type in (None, "commit"):
        tasks["commits"] = gitlab.search_project_commits(project_clean, search=search_term, per_page=15)

    results_raw = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results = {}
    for key, val in zip(tasks.keys(), results_raw):
        results[key] = _clean_list(_safe(val, []))

    # Merge and deduplicate issues
    all_issues = []
    seen = set()
    for key in ("issues_by_label", "issues_by_search"):
        for item in results.get(key, []):
            url = item.get("url", "")
            if url and url not in seen:
                seen.add(url)
                all_issues.append(item)

    all_mrs = []
    seen.clear()
    for key in ("mrs_by_label", "mrs_by_search"):
        for item in results.get(key, []):
            url = item.get("url", "")
            if url and url not in seen:
                seen.add(url)
                all_mrs.append(item)

    return {
        "project": project_clean,
        "keyword": keyword,
        "issues": all_issues,
        "merge_requests": all_mrs,
        "commits": results.get("commits", []),
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
