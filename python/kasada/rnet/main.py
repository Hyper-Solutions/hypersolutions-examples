"""
Kasada Bypass Example using rnet TLS client and Hyper Solutions SDK (Async)

This example demonstrates:
  - Setting up an async TLS client session with Chrome browser impersonation
  - Detecting Kasada protection (429 on page vs /fp endpoint)
  - Fetching and solving ips.js challenges
  - Generating payload data (CT) and POW tokens (CD)
  - Handling BotID verification when required
  - The complete flow from initial request to successful bypass

For more information, visit: https://docs.hypersolutions.co
Join our Discord community: https://discord.gg/akamai
"""

import asyncio
import base64
import os
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse

from rnet import Client, Proxy, HeaderMap, OrigHeaderMap, Jar, Cookie
from rnet.emulation import Emulation

from hyper_sdk import SessionAsync as HyperSession
from hyper_sdk import KasadaPayloadInput, KasadaPowInput, BotIDHeaderInput
from hyper_sdk.kasada import parse_script_path


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class Config:
    """Configuration for the Kasada bypass example."""

    # APIKey is your Hyper Solutions API key.
    # Get yours at: https://hypersolutions.co
    api_key: str

    # PageURL is the protected page you want to access.
    page_url: str

    # AcceptLanguage is the browser's accept-language header.
    accept_language: str = "en-US,en;q=0.9"

    # ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
    proxy_url: Optional[str] = None

    # Timeout is the HTTP request timeout in seconds.
    timeout: int = 30

    # BotIDEnabled enables BotID/Vercel protection solving.
    botid_enabled: bool = False


def default_config() -> Config:
    """Returns a sensible default configuration."""
    return Config(
        api_key=os.environ.get("HYPER_API_KEY", ""),
        page_url="https://example.com/protected-page",
        proxy_url=os.environ.get("HTTP_PROXY"),
    )


# =============================================================================
# BROWSER FINGERPRINT CONSTANTS
# =============================================================================

# User agent string for Chrome on Windows
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

# sec-ch-ua header value for Chrome 143
SEC_CH_UA = '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"'

# sec-ch-ua-platform header value
SEC_CH_UA_PLATFORM = '"Windows"'

# Kasada SDK version
KASADA_VERSION = "j-1.1.29140"

# Fixed Kasada paths
KASADA_BASE_PATH = "/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3"


# =============================================================================
# KASADA SOLVER
# =============================================================================

class KasadaSolver:
    """Handles the complete Kasada bypass flow using async rnet client."""

    def __init__(self, config: Config):
        if not config.api_key:
            raise ValueError("API key is required - get yours at https://hypersolutions.co")
        if not config.page_url:
            raise ValueError("Page URL is required")

        self.config = config

        # Parse domain from page URL
        parsed_url = urlparse(config.page_url)
        self.domain = parsed_url.netloc
        self.base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Create cookie jar for persistent cookies across requests
        self.cookie_jar = Jar()

        # Build proxy list if configured
        proxies = None
        if config.proxy_url:
            proxies = [Proxy.all(url=config.proxy_url)]

        # Create rnet async client with Chrome 143 emulation
        self.client = Client(
            emulation=Emulation.Chrome143,
            cookie_provider=self.cookie_jar,
            proxies=proxies,
            verify=False,  # Enable in production
        )

        # Create Hyper Solutions API session (async)
        self.hyper_api = HyperSession(config.api_key)

        # Internal state
        self.ip: str = ""
        self.ips_script: str = ""
        self.ips_link: str = ""

        # Headers from /tl response
        self.tl_ct: str = ""
        self.tl_st: int = 0

        # Headers from /mfc response
        self.mfc_fc: str = ""
        self.mfc_h: str = ""

    async def solve(self) -> bool:
        """
        Attempts to bypass Kasada protection and access the target page.
        Returns True if successful, False if blocked.
        """
        # Get public IP
        self.ip = await self._get_public_ip()
        print(f"Public IP: {self.ip}")

        print("Step 1: Making initial request to detect Kasada protection...")

        # Step 1: Fetch the page and check for 429
        status_code, page_body = await self._fetch_page()

        if status_code == 429:
            # Flow 1: 429 on page URL - solve and reload
            print("Step 2: Detected 429 on page, solving Kasada challenge...")
            await self._solve_from_block_page(page_body)

            # Reload page
            print("Step 3: Reloading page after solving...")
            status_code, _ = await self._fetch_page()

            if status_code != 200:
                print(f"Failed! Page still returning {status_code} after solve")
                return False

            print("  Page loaded successfully!")
        else:
            # Flow 2: No 429 on page - solve via /fp endpoint
            print("Step 2: No 429 on page, solving via /fp endpoint...")
            await self._solve_from_fp_endpoint()

        # Step 4: Handle BotID if enabled
        if self.config.botid_enabled:
            print("Step 4: Solving BotID challenge...")
            await self._solve_botid()
        else:
            print("Step 4: BotID disabled, skipping...")

        # Step 5: Generate POW (x-kpsdk-cd) for demonstration
        print("Step 5: Generating POW (x-kpsdk-cd) for API requests...")
        await self._generate_pow()

        print("\n✅ Kasada bypass successful!")
        return True

    async def _get_public_ip(self) -> str:
        """Retrieves the client's public IP address."""
        resp = await self.client.get("https://api.ipify.org")
        text = await resp.text()
        return text.strip()

    def _build_headers(self, header_dict: dict) -> HeaderMap:
        """Build a HeaderMap from a dictionary."""
        headers = HeaderMap()
        for key, value in header_dict.items():
            headers.insert(key, value)
        return headers

    def _build_header_order(self, order_list: list) -> OrigHeaderMap:
        """Build an OrigHeaderMap for header ordering."""
        header_order = OrigHeaderMap()
        for header_name in order_list:
            header_order.insert(header_name)
        return header_order

    def _get_cookie(self, name: str, url: str) -> str:
        """Retrieves a cookie value by name from the cookie jar."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme

        # Split hostname into parts and try progressively shorter domains
        parts = hostname.split(".")

        for i in range(len(parts)):
            if len(parts) - i < 2:
                break

            domain = ".".join(parts[i:])
            lookup_url = f"{scheme}://{domain}"
            cookie = self.cookie_jar.get(name, lookup_url)
            if cookie:
                return cookie.value

        return ""

    def _set_cookie(self, name: str, value: str, domain: str, url: str) -> None:
        """Sets a cookie in the cookie jar."""
        cookie = Cookie(
            name=name,
            value=value,
            domain=domain,
            path="/",
        )
        self.cookie_jar.add(cookie, url)

    async def _fetch_page(self) -> Tuple[int, str]:
        """Makes a GET request to the page URL."""
        headers = self._build_headers({
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=0, i",
        })

        header_order = self._build_header_order([
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests", "User-Agent", "Accept",
            "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
            "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
        ])

        resp = await self.client.get(
            self.config.page_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )

        status_code = resp.status.as_int()
        body = await resp.text()

        print(f"  Page response: {status_code}")

        return status_code, body

    async def _solve_from_block_page(self, block_page_body: str) -> None:
        """Handles the flow when page returns 429."""
        # Extract ips.js URL from block page
        ips_path = parse_script_path(block_page_body)
        self.ips_link = self.base_url + ips_path
        print(f"  IPS script URL: {self.ips_link}")

        # Fetch ips.js script
        await self._fetch_ips_script()

        # Generate and submit payload
        await self._solve_challenge()

    async def _solve_from_fp_endpoint(self) -> None:
        """Handles the flow when page doesn't return 429."""
        # Request /fp endpoint to trigger 429
        fp_url = f"{self.base_url}{KASADA_BASE_PATH}/fp?x-kpsdk-v={KASADA_VERSION}"

        headers = self._build_headers({
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "iframe",
            "Referer": self.config.page_url,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=0, i",
        })

        header_order = self._build_header_order([
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests", "User-Agent", "Accept",
            "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
            "Referer", "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
        ])

        resp = await self.client.get(
            fp_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )

        if resp.status.as_int() != 429:
            raise Exception(f"/fp returned unexpected status code: {resp.status.as_int()}")

        print("  /fp returned 429, extracting script...")

        body = await resp.text()

        # Extract ips.js URL
        ips_path = parse_script_path(body)
        self.ips_link = self.base_url + ips_path
        print(f"  IPS script URL: {self.ips_link}")

        # Fetch ips.js script
        await self._fetch_ips_script()

        # Generate and submit payload
        await self._solve_challenge()

    async def _fetch_ips_script(self) -> None:
        """Retrieves the ips.js script content."""
        headers = self._build_headers({
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "User-Agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "Accept": "*/*",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Dest": "script",
            "Referer": self.config.page_url,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=1",
        })

        header_order = self._build_header_order([
            "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
            "Referer", "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
        ])

        resp = await self.client.get(
            self.ips_link,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )

        if resp.status.as_int() != 200:
            raise Exception(f"ips.js request returned {resp.status.as_int()}")

        self.ips_script = await resp.text()
        print(f"  IPS script fetched: {len(self.ips_script)} bytes")

    async def _solve_challenge(self) -> None:
        """Generates payload and submits to /tl endpoint."""
        print("  Generating Kasada payload via Hyper API...")

        # Generate payload
        payload_b64, headers_dict = await self.hyper_api.generate_kasada_payload(
            KasadaPayloadInput(
                user_agent=USER_AGENT,
                ips_link=self.ips_link,
                script=self.ips_script,
                accept_language=self.config.accept_language,
                ip=self.ip,
            )
        )

        # Decode base64 payload
        payload = base64.b64decode(payload_b64)

        print("  Submitting payload to /tl...")

        # Submit to /tl
        tl_url = f"{self.base_url}{KASADA_BASE_PATH}/tl"

        # Start building headers dict
        req_headers_dict = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "User-Agent": USER_AGENT,
            "Content-Type": "application/octet-stream",
            "Accept": "*/*",
            "Origin": self.base_url,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": self.config.page_url,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=1, i",
        }

        # Build header order with Kasada headers at the front
        header_order_list = ["Content-Length"]

        # Add Kasada headers from payload generation
        for key, value in headers_dict.items():
            if value:
                req_headers_dict[key] = value
                header_order_list.append(key)

        header_order_list.extend([
            "sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile",
            "User-Agent", "Content-Type", "Accept", "Origin",
            "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
            "Referer", "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
        ])

        headers = self._build_headers(req_headers_dict)
        header_order = self._build_header_order(header_order_list)

        resp = await self.client.post(
            tl_url,
            headers=headers,
            orig_headers=header_order,
            body=payload,
            default_headers=False,
        )

        if resp.status.as_int() != 200:
            raise Exception(f"/tl returned {resp.status.as_int()}")

        # Check for reload:true
        tl_response = await resp.json()

        if not tl_response.get("reload"):
            raise Exception("/tl did not return reload:true")

        print("  /tl returned reload:true - challenge solved!")

        # Store headers for POW generation
        resp_headers = resp.headers
        self.tl_ct = resp_headers.get("x-kpsdk-ct")
        if self.tl_ct:
            self.tl_ct = self.tl_ct.decode("utf-8") if isinstance(self.tl_ct, bytes) else self.tl_ct
        else:
            self.tl_ct = ""

        st_val = resp_headers.get("x-kpsdk-st")
        if st_val:
            st_str = st_val.decode("utf-8") if isinstance(st_val, bytes) else st_val
            self.tl_st = int(st_str)
        else:
            self.tl_st = 0

        # Log response headers
        print("\n  Response headers from /tl:")
        print(f"    x-kpsdk-ct: {self.tl_ct}")
        print(f"    x-kpsdk-st: {self.tl_st}")

    async def _solve_botid(self) -> None:
        """Handles the BotID/Vercel verification."""
        # Fetch BotID script
        botid_url = f"{self.base_url}{KASADA_BASE_PATH}/a-4-a/c.js?i=0&v=3&h={self.domain}"

        headers = self._build_headers({
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "User-Agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "Accept": "*/*",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Dest": "script",
            "Referer": self.config.page_url,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
        })

        header_order = self._build_header_order([
            "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
            "Referer", "Accept-Encoding", "Accept-Language", "Cookie",
        ])

        resp = await self.client.get(
            botid_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )

        if resp.status.as_int() != 200:
            raise Exception(f"BotID script request returned {resp.status.as_int()}")

        script_text = await resp.text()
        print(f"  BotID script fetched: {len(script_text)} bytes")

        # Generate BotID header
        is_human_header = await self.hyper_api.generate_botid_header(
            BotIDHeaderInput(
                script=script_text,
                user_agent=USER_AGENT,
                ip=self.ip,
                accept_language=self.config.accept_language,
            )
        )

        print(f"  x-is-human header generated: {is_human_header[:50]}...")

    async def _generate_pow(self) -> None:
        """Generates the x-kpsdk-cd header for protected API requests."""
        # First, make /mfc request to get fc and h headers
        print("  Making /mfc request...")

        mfc_url = f"{self.base_url}{KASADA_BASE_PATH}/mfc"

        headers = self._build_headers({
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "x-kpsdk-h": "01",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "x-kpsdk-v": KASADA_VERSION,
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": self.config.page_url,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=1, i",
        })

        header_order = self._build_header_order([
            "sec-ch-ua-platform", "x-kpsdk-h", "sec-ch-ua", "sec-ch-ua-mobile",
            "x-kpsdk-v", "User-Agent", "Accept", "Sec-Fetch-Site",
            "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer",
            "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
        ])

        resp = await self.client.get(
            mfc_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )

        resp_headers = resp.headers

        fc_val = resp_headers.get("x-kpsdk-fc")
        if fc_val:
            self.mfc_fc = fc_val.decode("utf-8") if isinstance(fc_val, bytes) else fc_val
        else:
            self.mfc_fc = ""

        h_val = resp_headers.get("x-kpsdk-h")
        if h_val:
            self.mfc_h = h_val.decode("utf-8") if isinstance(h_val, bytes) else h_val
        else:
            self.mfc_h = ""

        print(f"  /mfc headers - x-kpsdk-fc: {self.mfc_fc[:30]}..., x-kpsdk-h: {self.mfc_h}")

        # Generate POW
        print("  Generating x-kpsdk-cd via Hyper API...")

        cd = await self.hyper_api.generate_kasada_pow(
            KasadaPowInput(
                st=self.tl_st,
                ct=self.tl_ct,
                fc=self.mfc_fc,
                domain=self.domain,
            )
        )

        print("\n  ✅ POW generated successfully!")
        print("\n  Headers for protected API requests:")
        print(f"    x-kpsdk-ct: {self.tl_ct}")
        print(f"    x-kpsdk-cd: {cd}")
        print(f"    x-kpsdk-h:  {self.mfc_h}")
        print(f"    x-kpsdk-v:  {KASADA_VERSION}")

    async def close(self) -> None:
        """Releases resources associated with the solver."""
        if self.hyper_api:
            await self.hyper_api.close()


# =============================================================================
# MAIN FUNCTION
# =============================================================================

async def main():
    # Load configuration
    config = default_config()

    # Configure for your target site
    config.page_url = "https://www.example.com/loyalty/en-US"

    # Enable BotID if the site uses Vercel BotID protection
    config.botid_enabled = False

    # Validate API key
    if not config.api_key:
        raise SystemExit(
            "HYPER_API_KEY environment variable not set. "
            "Get your API key at https://hypersolutions.co"
        )

    # Create and run solver
    solver = KasadaSolver(config)
    try:
        success = await solver.solve()

        if success:
            print("\nYou can now make authenticated requests using the same session.")
            print(
                "Remember to include x-kpsdk-ct, x-kpsdk-cd, x-kpsdk-h, and x-kpsdk-v headers on protected API requests.")
        else:
            print("\n❌ Kasada bypass failed.")
            print("The IP may be blocked or additional challenges are required.")
            raise SystemExit(1)
    finally:
        await solver.close()


if __name__ == "__main__":
    asyncio.run(main())