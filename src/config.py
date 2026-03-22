import os

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN", "")
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "")
PROJECTDISCOVERY_API_KEY = os.getenv("PROJECTDISCOVERY_API_KEY", "")

HTTP_TIMEOUT = 20
USER_AGENT = "MCP-CVE-Research/1.0"

HACKYX_TYPESENSE_URL = "https://api.hackyx.io"
HACKYX_API_KEY = "rbhL5yhPrBwYLVRTEubeqiALYzbVpPMT"
