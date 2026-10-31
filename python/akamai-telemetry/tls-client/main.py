"""
Akamai-BM-Telemetry Example using python-tls-client and Hyper Solutions SDK

Some Akamai sites never post sensor data: their protected API calls carry an
Akamai-BM-Telemetry header instead. This example walks the read-only part of
the resale flow on resale.paylogic.com:

  1. GET the resale page. It sets _abck and bm_sz and embeds the BM v3 script.
  2. GET the BM v3 script.
  3. get_telemetry_params with the script returns the site's get_params path
     and a context. GET that path on the page's origin and keep the "j" from
     its JSON response, verbatim.
  4. Call the protected API host, each call with a fresh Akamai-BM-Telemetry
     header from generate_telemetry that chains the previous call's context:
       GET /sales/<sale>                  returns the jwt_token
       GET /resale/<sale>                 with Authorization: Bearer <jwt_token>
       GET /ticket-transfer-approvals     the resale listing

The page's app calls the protected host cross-site without credentials, so
that host sees no cookies at all, only the header, and the browser sends a
CORS preflight before each call because the header is not a simple one.

The next step of the real flow, POST /baskets, reserves a ticket that cannot
be released again, so it is deliberately left out.

For more information, visit: https://docs.hypersolutions.co
Join our Discord community: https://discord.gg/akamai
"""

import os
import random
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import tls_client

from hyper_sdk import Session as HyperSession
from hyper_sdk import TelemetryInput, TelemetryParamsInput


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class Config:
    """Configuration for the Akamai-BM-Telemetry example."""

    # APIKey is your Hyper Solutions API key.
    # Get yours at: https://hypersolutions.co
    api_key: str

    # PageURL is the resale page: /<sale id>/<product category>.
    page_url: str

    # AcceptLanguage is the browser's accept-language header.
    accept_language: str = "en-US,en;q=0.9"

    # ApiLanguage is the accept-language the page's app sends on its API calls.
    api_language: str = "en"

    # ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
    proxy_url: Optional[str] = None

    # Timeout is the HTTP request timeout in seconds.
    timeout: int = 30


def default_config() -> Config:
    """Returns a sensible default configuration."""
    return Config(
        api_key=os.environ.get("HYPER_API_KEY", ""),
        page_url=os.environ.get(
            "PAGE_URL",
            "https://resale.paylogic.com/04b83148045e477f9e3f14874e989a3c/5f2afb6b648245a5bf082d395f83635e",
        ),
        proxy_url=os.environ.get("HTTP_PROXY"),
    )


# =============================================================================
# BROWSER FINGERPRINT CONSTANTS
# =============================================================================

# User agent string for Chrome on Windows
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

# sec-ch-ua header value for Chrome 143
SEC_CH_UA = '"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"'

# sec-ch-ua-platform header value
SEC_CH_UA_PLATFORM = '"Windows"'

# The protected API host the page's app calls
PROTECTED_API = "https://shopping-api.protected.paylogic.com"

# The BM v3 script tag carries no query (the SBSD tag on the same page does)
BM_SCRIPT_REGEX = re.compile(r'<script type="text/javascript"\s+src="(/[^"?]+)"')


# =============================================================================
# CLIENT HINTS
# =============================================================================

# Chrome sends these client hints on every request; any other hint only goes
# out once the site has asked for it in its Accept-CH response header.
LOW_ENTROPY_HINTS = ("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _insert_after_sec_ch(names: List[str], extra: List[str]) -> List[str]:
    """Inserts extra right after the last sec-ch-* name (at the end when there is none)."""
    present = {name.lower() for name in names}
    extra = [name for name in extra if name not in present]
    last = max((i for i, name in enumerate(names) if name.lower().startswith("sec-ch-")), default=len(names) - 1)
    return names[:last + 1] + extra + names[last + 1:]


class ClientHints:
    """Forwards the client_hints a generate call returned the way Chrome does.

    Until a generate call returns hints, the hardcoded SEC_CH_UA values above
    go out. Accept-CH is recorded per origin from navigation responses only;
    Chrome ignores it on the cross-site API responses, so the protected host
    only ever gets the low-entropy three.
    """

    def __init__(self) -> None:
        self.hints: Dict[str, str] = {}
        self.accept_ch: Dict[str, Set[str]] = {}

    def update(self, hints: Optional[Dict[str, str]]) -> None:
        """Stores the client_hints of a generate result (None when the API returned none)."""
        if hints:
            self.hints = dict(hints)

    def record(self, url: str, accept_ch) -> None:
        """Records the hints an origin asked for in its Accept-CH response header."""
        if not accept_ch:
            return
        if isinstance(accept_ch, bytes):
            accept_ch = accept_ch.decode()
        self.accept_ch[_origin(url)] = {name.strip().lower() for name in accept_ch.split(",") if name.strip()}

    def apply(self, url: str, headers: Dict[str, str], order: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """Returns headers and header order with the hints for url: the low-entropy
        three replace the defaults, the others the origin asked for go right after
        the last sec-ch-* header."""
        out = {
            name: self.hints.get(name.lower(), value) if name.lower() in LOW_ENTROPY_HINTS else value
            for name, value in headers.items()
        }
        if not any(name.lower().startswith("sec-ch-") for name in out):
            return out, list(order)

        requested = self.accept_ch.get(_origin(url), set())
        extra = [name for name in self.hints if name not in LOW_ENTROPY_HINTS and name in requested]
        keys = _insert_after_sec_ch(list(out), extra)
        return {name: out[name] if name in out else self.hints[name] for name in keys}, _insert_after_sec_ch(list(order), extra)


# =============================================================================
# COOKIE-LESS SESSION
# =============================================================================

class NoCookieSession(tls_client.Session):
    """A tls_client session without a cookie jar, like fetch() with credentials
    omitted: no Cookie header goes out and Set-Cookie is dropped. Both the
    Python jar and the Go library's own per-session jar are bypassed."""

    def _build_request_payload(self, *args, **kwargs) -> dict:
        payload = super()._build_request_payload(*args, **kwargs)
        payload["withoutCookieJar"] = True
        payload["requestCookies"] = []
        return payload


# =============================================================================
# TELEMETRY SOLVER
# =============================================================================

class TelemetrySolver:
    """Handles the Akamai-BM-Telemetry flow on resale.paylogic.com."""

    def __init__(self, config: Config):
        if not config.api_key:
            raise ValueError("API key is required - get yours at https://hypersolutions.co")

        parts = urlparse(config.page_url).path.strip("/").split("/")
        if len(parts) < 2:
            raise ValueError("Page URL must be https://resale.paylogic.com/<sale id>/<product category>")

        self.config = config
        self.origin = _origin(config.page_url)
        self.sale_id, self.product_category = parts[0], parts[1]

        # The page and its scripts run in one session with a cookie jar; the
        # protected API host gets its own session without one.
        self.session = tls_client.Session(
            client_identifier="chrome_133",
            random_tls_extension_order=True,
            disable_http3=True,
        )
        self.api_session = NoCookieSession(
            client_identifier="chrome_133",
            random_tls_extension_order=True,
            disable_http3=True,
        )

        for session in (self.session, self.api_session):
            session.timeout = config.timeout
            if config.proxy_url:
                session.proxies = {
                    "http": config.proxy_url,
                    "https": config.proxy_url,
                }

        # Create Hyper Solutions API session
        self.hyper_api = HyperSession(config.api_key)

        # Client hints from the latest generate call, forwarded like Chrome
        self.hints = ClientHints()

        # Internal state
        self.ip: str = ""
        self.script_url: str = ""
        self.script: str = ""
        self.j: str = ""
        self.abck: str = ""
        self.bmsz: str = ""
        self.telemetry_context: str = ""
        self.jwt: str = ""
        self.statuses: List[str] = []

    def solve(self) -> bool:
        """Runs the read-only flow. Returns True when every protected call returned 200."""
        self.ip = self._get_public_ip()
        print(f"Public IP: {self.ip}")

        print("Step 1: Fetching the resale page...")
        self._fetch_page()

        print("Step 2: Fetching the BM v3 script...")
        self._fetch_script()

        print("Step 3: Fetching the telemetry params (j)...")
        self._fetch_params()

        # The header carries the page-load cookies. The protected responses set
        # their own bm_sz, but the browser never stores it (credentials omitted).
        cookies = self.session.cookies.get_dict()
        self.abck = cookies.get("_abck", "")
        self.bmsz = cookies.get("bm_sz", "")
        if not self.abck or not self.bmsz:
            raise RuntimeError("_abck or bm_sz missing after the page load")

        # A user spends a moment on the page before the app's first API call
        _sleep_ms(2500, 1500)

        print("Step 4: Calling the protected API with Akamai-BM-Telemetry...")
        status, sale = self._protected(f"/sales/{self.sale_id}")
        if status != 200 or not sale or not sale.get("jwt_token"):
            return False
        self.jwt = sale["jwt_token"]

        _sleep_ms(900, 400)
        status, _ = self._protected(f"/resale/{self.sale_id}", bearer=True)
        if status != 200:
            return False

        _sleep_ms(900, 400)
        sale_url = f"{PROTECTED_API}/sales/{self.sale_id}"
        status, approvals = self._protected(
            f"/ticket-transfer-approvals?sale={sale_url}&product_category={self.product_category}"
        )
        if status != 200:
            return False

        listed = (approvals or {}).get("_embedded", {}).get("shop:ticket_transfer_approval", [])
        print(f"  Resale listing: {len(listed)} ticket transfer approval(s)")

        # POST /baskets would reserve one of those tickets for good: not done here.
        return True

    def _get_public_ip(self) -> str:
        """Retrieves the client's public IP address."""
        resp = self.session.get("https://api.ipify.org")
        return resp.text.strip()

    def _get(self, url: str, headers: Dict[str, str], order: List[str]):
        """GETs a page-origin URL with the client hints for it, in the page's session."""
        self.session.headers, self.session.header_order = self.hints.apply(url, headers, order)
        return self.session.get(url)

    def _fetch_page(self) -> None:
        """Navigates to the resale page and finds the BM v3 script tag."""
        resp = self._get(self.config.page_url, {
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        }, [
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
            "sec-fetch-dest", "accept-encoding", "accept-language", "cookie",
        ])
        self.statuses.append(f"page={resp.status_code}")
        print(f"  Page: {resp.status_code}")
        if resp.status_code != 200:
            raise RuntimeError(f"Resale page returned {resp.status_code}")

        # A navigation response is where Chrome takes Accept-CH from
        self.hints.record(self.config.page_url, resp.headers.get("accept-ch"))

        match = BM_SCRIPT_REGEX.search(resp.text)
        if not match:
            raise RuntimeError("BM v3 script tag not found on the page")

        # The script's absolute URL is also the TelemetryInput.script_url
        self.script_url = self.origin + match.group(1)
        print(f"  BM script: {self.script_url}")

    def _script_headers(self, mode: str, dest: str) -> Tuple[Dict[str, str], List[str]]:
        """Returns the headers of a same-origin script or fetch request."""
        headers = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": mode,
            "sec-fetch-dest": dest,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        }
        order = [
            "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "accept-encoding", "accept-language", "cookie",
        ]
        return headers, order

    def _fetch_script(self) -> None:
        """Retrieves the BM v3 script content."""
        resp = self._get(self.script_url, *self._script_headers("no-cors", "script"))
        if resp.status_code != 200:
            raise RuntimeError(f"BM script returned {resp.status_code}")

        self.script = resp.text
        print(f"  Script fetched: {len(self.script)} bytes")

    def _fetch_params(self) -> None:
        """Gets the get_params path from the API, requests it and keeps the j."""
        params = self.hyper_api.get_telemetry_params(
            TelemetryParamsInput(
                page_url=self.config.page_url,
                script=self.script,
            )
        )

        # The params context replaces the script on the first telemetry request
        self.telemetry_context = params.context

        params_url = self.origin + params.path
        resp = self._get(params_url, *self._script_headers("cors", "empty"))
        print(f"  get_params: {resp.status_code}")
        if resp.status_code != 200:
            raise RuntimeError(f"get_params returned {resp.status_code}: {resp.text[:200]}")

        # j goes into every TelemetryInput exactly as the site returned it
        self.j = resp.json()["j"]

    def _telemetry(self) -> str:
        """Builds the next Akamai-BM-Telemetry value, chaining the previous context."""
        result = self.hyper_api.generate_telemetry(
            TelemetryInput(
                abck=self.abck,
                bmsz=self.bmsz,
                page_url=self.config.page_url,
                user_agent=USER_AGENT,
                ip=self.ip,
                accept_language=self.config.accept_language,
                context=self.telemetry_context,
                # The context carries the script, so it is not sent again
                script="",
                script_url=self.script_url,
                j=self.j,
            )
        )

        self.telemetry_context = result.context
        self.hints.update(result.client_hints)
        return result.header

    def _api_send(self, method: str, url: str, headers: Dict[str, str], order: List[str]):
        """Sends a request to the protected host: cross-site, no cookies either way."""
        self.api_session.headers, self.api_session.header_order = self.hints.apply(url, headers, order)
        return self.api_session.execute_request(method, url)

    def _preflight(self, url: str, request_headers: str) -> None:
        """Sends the CORS preflight a browser makes before the protected call."""
        resp = self._api_send("OPTIONS", url, {
            "accept": "*/*",
            "access-control-request-method": "GET",
            "access-control-request-headers": request_headers,
            "origin": self.origin,
            "user-agent": USER_AGENT,
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "sec-fetch-dest": "empty",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        }, [
            "accept", "access-control-request-method", "access-control-request-headers",
            "origin", "user-agent", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest",
            "accept-encoding", "accept-language",
        ])
        print(f"  OPTIONS {urlparse(url).path}: {resp.status_code}")

    def _protected(self, path: str, bearer: bool = False) -> Tuple[int, Optional[dict]]:
        """GETs a protected API path with a fresh telemetry header and returns the
        status and, for a 2xx, the decoded JSON body."""
        url = PROTECTED_API + path
        label = path.lstrip("/").split("/")[0].split("?")[0]

        self._preflight(url, "akamai-bm-telemetry,authorization" if bearer else "akamai-bm-telemetry")

        headers = {
            "akamai-bm-telemetry": self._telemetry(),
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "accept-language": self.config.api_language,
            "accept": "application/json, text/plain, */*",
            "sec-ch-ua": SEC_CH_UA,
            "user-agent": USER_AGENT,
            "sec-ch-ua-mobile": "?0",
            "origin": self.origin,
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-encoding": "gzip, deflate, br, zstd",
        }
        if bearer:
            headers["authorization"] = f"Bearer {self.jwt}"
            # Angular's Authorization header shifts the order
            order = [
                "akamai-bm-telemetry", "sec-ch-ua-platform", "authorization", "accept-language",
                "sec-ch-ua", "sec-ch-ua-mobile", "user-agent", "accept", "origin",
                "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding",
            ]
        else:
            order = [
                "akamai-bm-telemetry", "sec-ch-ua-platform", "accept-language", "accept",
                "sec-ch-ua", "user-agent", "sec-ch-ua-mobile", "origin",
                "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding",
            ]

        resp = self._api_send("GET", url, headers, order)
        self.statuses.append(f"{label}={resp.status_code}")
        print(f"  GET {label}: {resp.status_code}")

        if not 200 <= resp.status_code < 300:
            print(f"    {resp.text[:300]}")
            return resp.status_code, None
        return resp.status_code, resp.json()

    def close(self) -> None:
        """Releases resources associated with the solver."""
        if self.hyper_api:
            self.hyper_api.close()


def _sleep_ms(base: int, jitter: int) -> None:
    time.sleep((base + random.randint(0, jitter)) / 1000)


# =============================================================================
# MAIN FUNCTION
# =============================================================================

def main():
    # Load configuration (HYPER_API_KEY, HTTP_PROXY and optionally PAGE_URL)
    config = default_config()

    # Validate API key
    if not config.api_key:
        raise SystemExit(
            "HYPER_API_KEY environment variable not set. "
            "Get your API key at https://hypersolutions.co"
        )

    solver = TelemetrySolver(config)
    try:
        success = solver.solve()
        print(f"\nStatuses: {' '.join(solver.statuses)}")

        if success:
            print("✅ Every protected call returned 200 with the Akamai-BM-Telemetry header.")
        else:
            print("❌ A protected call was refused.")
            raise SystemExit(1)
    finally:
        solver.close()


if __name__ == "__main__":
    main()
