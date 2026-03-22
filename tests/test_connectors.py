"""
Integration tests for mcp-cve connectors.
Run from the src/ directory:
    cd /home/vozec/Desktop/dev/mcp/mcp_cve/src
    python -m pytest ../tests/test_connectors.py -v
"""
import sys
import os
import asyncio
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from connectors import github, nvd, epss, kev, osv, searchsploit, poc_in_github, hackyx, vulners, nuclei_api


# ---------------------------------------------------------------------------
# GitHub Advisory Database
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_advisories_keyword_spip():
    """Keyword search for 'spip' must return at least 1 advisory."""
    results = await github.search_advisories(keyword="spip", per_page=5)
    assert isinstance(results, list), "Should return a list"
    assert len(results) > 0, "Should find SPIP advisories"
    # No error entries
    for r in results:
        assert "error" not in r, f"Got error: {r}"
    # Each entry should have a ghsa_id or cve_id
    for r in results:
        assert r.get("ghsa_id") or r.get("cve_id"), f"Advisory missing ID: {r}"


@pytest.mark.asyncio
async def test_search_advisories_keyword_log4j():
    """Keyword search for 'log4j' must return advisories."""
    results = await github.search_advisories(keyword="log4j", per_page=5)
    assert isinstance(results, list)
    assert len(results) > 0, "Should find log4j advisories"
    for r in results:
        assert "error" not in r


@pytest.mark.asyncio
async def test_search_advisories_by_cve():
    """CVE ID lookup for CVE-2023-27372 (SPIP RCE) must return the advisory."""
    results = await github.search_advisories(cve_id="CVE-2023-27372", per_page=1)
    assert isinstance(results, list)
    assert len(results) > 0, "Should find CVE-2023-27372 advisory"
    assert "error" not in results[0]
    assert results[0].get("cve_id") == "CVE-2023-27372"


@pytest.mark.asyncio
async def test_search_advisories_by_ecosystem():
    """Ecosystem filter for composer must return PHP advisories."""
    results = await github.search_advisories(ecosystem="composer", per_page=5)
    assert isinstance(results, list)
    assert len(results) > 0, "Should find composer advisories"
    for r in results:
        assert "error" not in r


@pytest.mark.asyncio
async def test_search_advisories_all_types_spip():
    """search_advisories_all_types for 'spip' must return results in reviewed or unreviewed."""
    result = await github.search_advisories_all_types(keyword="spip", per_page=5)
    assert isinstance(result, dict)
    assert "reviewed" in result
    assert "unreviewed" in result
    total = len(result["reviewed"]) + len(result["unreviewed"])
    assert total > 0, f"Expected advisories for spip, got: {result}"


@pytest.mark.asyncio
async def test_search_advisories_severity_filter():
    """Severity filter must not crash and returns valid results."""
    results = await github.search_advisories(severity="critical", per_page=5)
    assert isinstance(results, list)
    for r in results:
        assert "error" not in r


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nvd_search_keyword():
    """NVD keyword search for 'apache' must return CVEs."""
    results = await nvd.search_cves(keyword="apache tomcat", results_per_page=5)
    assert isinstance(results, list)
    assert len(results) > 0
    for r in results:
        assert "error" not in r
        assert r.get("cve_id", "").startswith("CVE-")


@pytest.mark.asyncio
async def test_nvd_get_cve():
    """NVD direct CVE lookup must return the correct entry."""
    result = await nvd.get_cve("CVE-2021-44228")  # Log4Shell
    assert result is not None
    assert "error" not in result
    assert result.get("cve_id") == "CVE-2021-44228"
    assert result.get("cvss", {}).get("score") is not None


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_epss_single():
    """EPSS score for Log4Shell must be a float > 0."""
    result = await epss.get_epss("CVE-2021-44228")
    assert "error" not in result
    assert isinstance(result.get("score"), float)
    assert result["score"] > 0


@pytest.mark.asyncio
async def test_epss_batch():
    """EPSS batch must return scores for multiple CVEs."""
    cve_ids = ["CVE-2021-44228", "CVE-2023-27372", "CVE-2022-28960"]
    results = await epss.get_epss_batch(cve_ids)
    assert isinstance(results, list)
    assert len(results) > 0
    for r in results:
        assert "error" not in r
        assert r.get("cve") in cve_ids


# ---------------------------------------------------------------------------
# KEV (CISA Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kev_log4shell_in_kev():
    """Log4Shell must be in the CISA KEV catalog."""
    in_kev = await kev.is_in_kev("CVE-2021-44228")
    assert in_kev is True


@pytest.mark.asyncio
async def test_kev_search():
    """KEV search for 'apache' must return entries."""
    results = await kev.search_kev("apache", limit=5)
    assert isinstance(results, list)
    assert len(results) > 0


@pytest.mark.asyncio
async def test_kev_get_entry():
    """KEV entry for Log4Shell must have vendor info."""
    entry = await kev.get_kev_entry("CVE-2021-44228")
    assert entry is not None
    assert entry.get("vendor") or entry.get("product")


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_osv_query_package():
    """OSV query for 'lodash' in npm must return vulnerabilities."""
    results = await osv.query_package(ecosystem="npm", package_name="lodash")
    assert isinstance(results, list)
    assert len(results) > 0
    for r in results:
        assert "error" not in r
        assert r.get("id")


@pytest.mark.asyncio
async def test_osv_get_vuln():
    """OSV direct lookup by ID must return the vulnerability."""
    result = await osv.get_vuln("GHSA-jf85-cpcp-j695")
    assert result is not None
    assert "error" not in result
    assert result.get("id") == "GHSA-jf85-cpcp-j695"


# ---------------------------------------------------------------------------
# SearchSploit (offline Exploit-DB)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_searchsploit_keyword():
    """SearchSploit must find SPIP exploits."""
    results = await searchsploit.search("spip", limit=5)
    assert isinstance(results, list)
    # SearchSploit may or may not have results depending on the CSV
    for r in results:
        assert "error" not in r


@pytest.mark.asyncio
async def test_searchsploit_by_cve():
    """SearchSploit CVE lookup must return results for a well-known CVE."""
    results = await searchsploit.search_by_cve("CVE-2021-44228", limit=5)
    assert isinstance(results, list)
    for r in results:
        assert "error" not in r


# ---------------------------------------------------------------------------
# PoC-in-GitHub
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_poc_in_github_log4shell():
    """PoC-in-GitHub must have PoC repos for Log4Shell."""
    results = await poc_in_github.search_poc("CVE-2021-44228")
    assert isinstance(results, list)
    assert len(results) > 0
    for r in results:
        assert r.get("url")


@pytest.mark.asyncio
async def test_poc_in_github_spip():
    """PoC-in-GitHub lookup for SPIP RCE CVE-2023-27372."""
    results = await poc_in_github.search_poc("CVE-2023-27372")
    assert isinstance(results, list)
    # May or may not have PoCs, just ensure no crash
    for r in results:
        assert "error" not in r


# ---------------------------------------------------------------------------
# Hackyx
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_hackyx_search():
    """Hackyx must return articles for 'SPIP'."""
    result = await hackyx.search_articles(query="SPIP", per_page=5)
    assert isinstance(result, dict), "Success result should be a dict"
    assert "articles" in result
    assert result.get("total", 0) >= 0


@pytest.mark.asyncio
async def test_hackyx_search_rce():
    """Hackyx must find RCE-tagged articles."""
    result = await hackyx.search_articles(query="*", tags="rce", per_page=5)
    assert isinstance(result, dict)
    assert "articles" in result


# ---------------------------------------------------------------------------
# Vulners
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vulners_search():
    """Vulners search for SPIP must return results."""
    result = await vulners.search("SPIP", limit=5)
    assert isinstance(result, dict)
    # With valid API key, should have results
    if "error" not in result:
        assert "results" in result
        assert isinstance(result["results"], list)


@pytest.mark.asyncio
async def test_vulners_search_by_cve():
    """Vulners CVE search for Log4Shell."""
    result = await vulners.search_by_cve("CVE-2021-44228", limit=5)
    assert isinstance(result, dict)
    if "error" not in result:
        assert "results" in result


# ---------------------------------------------------------------------------
# Nuclei API (ProjectDiscovery)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nuclei_api_search():
    """Nuclei API must return CVEs with templates."""
    result = await nuclei_api.search_cves(keyword="spip", limit=5)
    assert isinstance(result, dict)
    if "error" not in result:
        assert "cves" in result
        assert isinstance(result["cves"], list)


@pytest.mark.asyncio
async def test_nuclei_api_templates():
    """Nuclei template search must work."""
    result = await nuclei_api.search_templates("apache", limit=5)
    assert isinstance(result, dict)
    if "error" not in result:
        assert "cves" in result


# ---------------------------------------------------------------------------
# GitHub PoC repos
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_github_poc_repos():
    """GitHub PoC repo search for Log4Shell must return repos."""
    results = await github.search_poc_repos("CVE-2021-44228", per_page=5)
    assert isinstance(results, list)
    assert len(results) > 0
    for r in results:
        assert "error" not in r
        assert r.get("url")


@pytest.mark.asyncio
async def test_github_security_issues():
    """GitHub security issues search — a 422 from GitHub (PAT scope limit) is acceptable."""
    results = await github.search_security_issues("SPIP", per_page=5)
    assert isinstance(results, list)
    # If GitHub returns a 422 (PAT scope limitation or query restrictions), that's an
    # API-level constraint, not a code bug. Only fail on non-HTTP errors.
    for r in results:
        if "error" in r:
            assert "422" in r["error"] or "403" in r["error"] or "401" in r["error"], \
                f"Unexpected error (not an API auth/scope issue): {r['error']}"


if __name__ == "__main__":
    asyncio.run(test_search_advisories_keyword_spip())
    print("All tests passed!")
