import csv
import io
import httpx
from typing import Optional
from config import HTTP_TIMEOUT
from cache import cache_get, cache_set

CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOIT_BASE_URL = "https://www.exploit-db.com/exploits"
RAW_BASE_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main"

_exploits_db: Optional[list[dict]] = None


async def _load_db() -> list[dict]:
    global _exploits_db

    if _exploits_db is not None:
        return _exploits_db

    cached = await cache_get("mcp_cve:searchsploit:db")
    if cached is not None:
        _exploits_db = cached
        return cached

    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            resp = await client.get(CSV_URL)
            resp.raise_for_status()
            raw = resp.text
    except Exception:
        _exploits_db = []
        return []

    reader = csv.DictReader(io.StringIO(raw))
    entries = []
    for row in reader:
        entries.append({
            "id": row.get("id", ""),
            "file": row.get("file", ""),
            "description": row.get("description", ""),
            "date_published": row.get("date_published", ""),
            "author": row.get("author", ""),
            "platform": row.get("platform", ""),
            "type": row.get("type", ""),
            "port": row.get("port", ""),
            "codes": row.get("codes", ""),  # CVE codes etc
        })

    _exploits_db = entries
    await cache_set("mcp_cve:searchsploit:db", entries, ttl=86400)
    return entries


async def search(
    keyword: str,
    platform: Optional[str] = None,
    exploit_type: Optional[str] = None,
    limit: int = 25,
) -> list[dict]:
    """Search the Exploit-DB database (searchsploit equivalent)."""
    db = await _load_db()
    if not db:
        return [{"error": "Failed to load Exploit-DB database"}]

    keyword_lower = keyword.lower()
    keywords = keyword_lower.split()
    results = []

    for entry in db:
        desc = entry.get("description", "").lower()
        codes = entry.get("codes", "").lower()
        plat = entry.get("platform", "").lower()
        etype = entry.get("type", "").lower()

        # All keywords must match in description or codes
        if not all(kw in desc or kw in codes for kw in keywords):
            continue

        if platform and platform.lower() not in plat:
            continue

        if exploit_type and exploit_type.lower() not in etype:
            continue

        edb_id = entry.get("id", "")
        file_path = entry.get("file", "")

        results.append({
            "edb_id": edb_id,
            "title": entry.get("description", ""),
            "date": entry.get("date_published", ""),
            "author": entry.get("author", ""),
            "platform": entry.get("platform", ""),
            "type": entry.get("type", ""),
            "port": entry.get("port", ""),
            "codes": entry.get("codes", ""),
            "url": f"{EXPLOIT_BASE_URL}/{edb_id}" if edb_id else "",
            "raw_url": f"{RAW_BASE_URL}/{file_path}" if file_path else "",
        })

        if len(results) >= limit:
            break

    return results


async def search_by_cve(cve_id: str, limit: int = 10) -> list[dict]:
    """Search Exploit-DB by CVE identifier."""
    db = await _load_db()
    if not db:
        return []

    cve_upper = cve_id.upper()
    results = []
    for entry in db:
        codes = entry.get("codes", "").upper()
        if cve_upper in codes:
            edb_id = entry.get("id", "")
            file_path = entry.get("file", "")
            results.append({
                "edb_id": edb_id,
                "title": entry.get("description", ""),
                "date": entry.get("date_published", ""),
                "author": entry.get("author", ""),
                "platform": entry.get("platform", ""),
                "type": entry.get("type", ""),
                "codes": entry.get("codes", ""),
                "url": f"{EXPLOIT_BASE_URL}/{edb_id}" if edb_id else "",
                "raw_url": f"{RAW_BASE_URL}/{file_path}" if file_path else "",
            })
            if len(results) >= limit:
                break

    return results
