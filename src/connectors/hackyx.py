import json
import httpx
from typing import Optional
from config import HACKYX_TYPESENSE_URL, HACKYX_API_KEY, HTTP_TIMEOUT
from cache import cache_get, cache_set, make_key

COLLECTION = "contents"
SEARCH_FIELDS = "title, description, tags, content, cwe, program, source"


async def search_articles(
    query: str = "*",
    tags: Optional[str] = None,
    cwe: Optional[str] = None,
    source: Optional[str] = None,
    page: int = 1,
    per_page: int = 10,
) -> list[dict]:
    cache_key = make_key("hackyx", query=query, tags=tags, cwe=cwe, source=source, page=page)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    filters = []
    if tags:
        filters.append(f"tags:=[`{tags}`]")
    if cwe:
        filters.append(f"cwe:=[`{cwe}`]")
    if source:
        filters.append(f"source:=[`{source}`]")

    filter_by = " && ".join(filters) if filters else ""

    search_params = {
        "query_by": SEARCH_FIELDS,
        "num_typos": "1",
        "typo_tokens_threshold": 1,
        "prefix": False,
        "highlight_full_fields": SEARCH_FIELDS,
        "collection": COLLECTION,
        "q": query,
        "facet_by": "cwe,program,source,tags",
        "max_facet_values": 10,
        "page": page,
        "per_page": per_page,
    }
    if filter_by:
        search_params["filter_by"] = filter_by

    payload = {"searches": [search_params]}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post(
                f"{HACKYX_TYPESENSE_URL}/multi_search",
                headers={
                    "X-Typesense-Api-Key": HACKYX_API_KEY,
                    "Content-Type": "text/plain",
                },
                content=json.dumps(payload),
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return [{"error": f"Hackyx search error: {e}"}]

    results_data = data.get("results", [{}])
    first = results_data[0] if results_data else {}

    hits = []
    for h in first.get("hits", []):
        doc = h.get("document", {})
        hits.append({
            "title": doc.get("title", ""),
            "description": doc.get("description", "")[:300],
            "url": doc.get("url", ""),
            "tags": doc.get("tags", []),
            "cwe": doc.get("cwe", []),
            "source": doc.get("source", ""),
            "program": doc.get("program", ""),
        })

    result = {
        "total": first.get("found", 0),
        "articles": hits,
    }

    await cache_set(cache_key, result, ttl=1800)
    return result
