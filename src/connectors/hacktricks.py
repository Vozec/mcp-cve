import httpx
from config import GITHUB_TOKEN, HTTP_TIMEOUT, USER_AGENT
from cache import cache_get, cache_set, make_key

API_URL = "https://api.github.com"
REPO = "HackTricks-wiki/hacktricks"
CLOUD_REPO = "HackTricks-wiki/hacktricks-cloud"
BOOK_URL = "https://book.hacktricks.wiki/en"


def _headers() -> dict:
    h = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


async def search(keyword: str, per_page: int = 15) -> list[dict]:
    """Search HackTricks repo for pages related to a keyword/technology.

    Searches both the main hacktricks repo and hacktricks-cloud.
    Returns matching markdown pages with links to the book.
    """
    cache_key = make_key("hacktricks", keyword=keyword, per_page=per_page)
    cached = await cache_get(cache_key)
    if cached is not None:
        return cached

    results = []

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            # Search main repo
            resp = await client.get(
                f"{API_URL}/search/code",
                params={
                    "q": f"{keyword} repo:{REPO} language:markdown",
                    "per_page": per_page,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("items", []):
                path = item.get("path", "")
                name = item.get("name", "")
                # Convert repo path to book URL
                # e.g. src/pentesting-web/ssrf.md -> https://book.hacktricks.wiki/en/pentesting-web/ssrf.md
                book_path = path
                if book_path.startswith("src/"):
                    book_path = book_path[4:]

                results.append({
                    "title": name.replace(".md", "").replace("-", " ").title(),
                    "path": path,
                    "book_url": f"{BOOK_URL}/{book_path}" if not path.startswith(".") else "",
                    "github_url": f"https://github.com/{REPO}/blob/master/{path}",
                    "repo": "hacktricks",
                })

            # Search cloud repo too
            resp2 = await client.get(
                f"{API_URL}/search/code",
                params={
                    "q": f"{keyword} repo:{CLOUD_REPO} language:markdown",
                    "per_page": 5,
                },
            )
            resp2.raise_for_status()
            data2 = resp2.json()

            for item in data2.get("items", []):
                path = item.get("path", "")
                name = item.get("name", "")
                results.append({
                    "title": name.replace(".md", "").replace("-", " ").title(),
                    "path": path,
                    "book_url": f"https://cloud.hacktricks.wiki/en/{path}",
                    "github_url": f"https://github.com/{CLOUD_REPO}/blob/master/{path}",
                    "repo": "hacktricks-cloud",
                })

    except Exception as e:
        return [{"error": f"HackTricks search error: {e}"}]

    await cache_set(cache_key, results, ttl=3600)
    return results
