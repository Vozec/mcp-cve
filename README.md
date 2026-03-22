# mcp-cve

A [Model Context Protocol](https://modelcontextprotocol.io/) server for vulnerability intelligence.

Search CVEs, exploits, PoCs, attack surfaces, writeups, and recon data across 15+ sources — directly from your AI assistant.

## Tools

| Tool | Description |
|------|-------------|
| `get_technology_profile` | Identity card of a technology: CVE count, exposure, recent vulns, dorks |
| `search_vulns` | Search CVEs for a software, sorted by exploitability (KEV > EPSS > CVSS) |
| `get_cve_details` | Full details of a CVE: scores, exploits, PoCs, writeups, fix commits |
| `search_exploits` | Search exploits and PoCs across all sources for a CVE or software |
| `get_attack_surface` | Historical CVE distribution by CWE, severity, and year |
| `search_writeups` | Search security writeups and bug bounty reports |
| `search_github_security` | GitHub/GitLab issues, PRs, commits, and advisories |
| `search_package_vulns` | OSV + GHSA vulnerabilities for an open source package |
| `get_recon_data` | Shodan exposure stats and ready-to-use dorks |
| `get_default_credentials` | Default credentials and common misconfigurations |
| `compare_technologies` | Side-by-side security posture of two technologies |
| `get_vuln_timeline` | Timeline from disclosure to exploitation |
| `search_by_cwe` | Find all CVEs matching a weakness class (CWE ID or name) |
| `searchsploit_search` | Offline Exploit-DB search (~50k exploits) |
| `get_security_resources` | Writeups, cheatsheets, and exploit entries for any topic |
| `search_vulners` | Lucene-syntax search across the Vulners database |
| `search_nuclei_pocs` | CVEs with Nuclei templates or known PoCs (ProjectDiscovery) |
| `search_advisories` | GitHub Advisory Database (reviewed + unreviewed) |
| `search_gitlab_security` | GitLab project security signals |

## Quick Start

```bash
git clone https://github.com/Vozec/mcp-cve.git
cd mcp-cve
cp .env.example .env
# Fill in your API keys
docker compose up -d
```

The MCP endpoint is available at `http://localhost:8000/mcp` (Streamable HTTP).

## Connect to Claude

```bash
claude mcp add mcp-cve --transport http http://localhost:8000/mcp
```

Or add manually to your MCP config:

```json
{
  "mcpServers": {
    "mcp-cve": {
      "type": "http",
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

## API Keys

All keys are optional — tools degrade gracefully when a key is missing.

| Variable | Required for | Link |
|----------|-------------|------|
| `NVD_API_KEY` | Higher NVD rate limits | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| `GITHUB_TOKEN` | GitHub search tools | [github.com/settings/tokens](https://github.com/settings/tokens) |
| `GITLAB_TOKEN` | GitLab search tools | [gitlab.com/-/user_settings/personal_access_tokens](https://gitlab.com/-/user_settings/personal_access_tokens) |
| `SHODAN_API_KEY` | Recon / exposure data | [account.shodan.io](https://account.shodan.io) |
| `VULNERS_API_KEY` | Vulners search | [vulners.com/userinfo](https://vulners.com/userinfo) |
| `PROJECTDISCOVERY_API_KEY` | Nuclei PoC search | [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io) |
