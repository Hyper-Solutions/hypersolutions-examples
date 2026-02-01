"""
Akamai Bot Manager Bypass Example using rnet TLS client and Hyper Solutions SDK (Async)

This example demonstrates:
  - Setting up an async TLS client session with Chrome browser impersonation
  - Detecting and solving SBSD (State-Based Scraping Detection) challenges
  - Handling SBSD with and without the "t" parameter
  - Generating and submitting sensor data via the Hyper API
  - Cookie validation and the complete bypass flow

For more information, visit: https://docs.hypersolutions.co
Join our Discord community: https://discord.gg/akamai
"""

import asyncio
import json
import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from rnet import Client, Emulation, Proxy, Jar, HeaderMap, OrigHeaderMap

from hyper_sdk import SessionAsync as HyperSession
from hyper_sdk import SensorInput, SbsdInput
from hyper_sdk.akamai import parse_script_path, is_cookie_valid


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class Config:
    """Configuration for the Akamai bypass example."""

    # APIKey is your Hyper Solutions API key.
    # Get yours at: https://hypersolutions.co
    api_key: str

    # TargetURL is the protected page you want to access.
    target_url: str

    # Referer is the HTTP referer header value.
    # Usually the same as TargetURL or the base domain.
    referer: str

    # AcceptLanguage is the browser's accept-language header.
    accept_language: str = "en-US,en;q=0.9"

    # ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
    proxy_url: Optional[str] = None

    # Timeout is the HTTP request timeout in seconds.
    timeout: int = 30

    # Version is the Akamai version (usually "2" or "3").
    version: str = "3"


def default_config() -> Config:
    """Returns a sensible default configuration."""
    return Config(
        api_key=os.environ.get("HYPER_API_KEY", ""),
        target_url="https://example.com/protected-page",
        referer="https://example.com/",
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

# SBSD regex pattern
SBSD_REGEX = re.compile(r'(?i)([a-z\d/\-_\.]+)\?v=(.*?)(?:&.*?t=(.*?))?["\']')


# =============================================================================
# SBSD INFO
# =============================================================================

@dataclass
class SbsdInfo:
    """Holds extracted SBSD information from the page."""
    path: str  # Script path (e.g., /abc/def)
    uuid: str  # UUID/version parameter
    t: str = ""  # Optional "t" parameter (indicates hardblock if present)

    def is_hardblock(self) -> bool:
        """Returns True if SBSD is in hardblock mode (t parameter present)."""
        return self.t != ""

    def script_url(self, base_url: str) -> str:
        """Returns the full URL to fetch the SBSD script."""
        parsed = urlparse(base_url)
        script_url = f"{parsed.scheme}://{parsed.netloc}{self.path}?v={self.uuid}"
        if self.t:
            script_url += f"&t={self.t}"
        return script_url

    def post_url(self, base_url: str) -> str:
        """Returns the URL for posting SBSD payloads."""
        parsed = urlparse(base_url)
        post_url = f"{parsed.scheme}://{parsed.netloc}{self.path}"
        if self.t:
            post_url += f"?t={self.t}"
        return post_url


def parse_sbsd_info(html: str) -> Optional[SbsdInfo]:
    """Attempts to extract SBSD information from page HTML."""
    matches = SBSD_REGEX.search(html)
    if not matches:
        return None

    info = SbsdInfo(
        path=matches.group(1),
        uuid=matches.group(2),
    )

    if matches.group(3):
        info.t = matches.group(3)

    return info


# =============================================================================
# AKAMAI SOLVER
# =============================================================================

class AkamaiSolver:
    """Handles the complete Akamai bypass flow using async rnet client."""

    def __init__(self, config: Config):
        if not config.api_key:
            raise ValueError("API key is required - get yours at https://hypersolutions.co")
        if not config.target_url:
            raise ValueError("Target URL is required")

        self.config = config

        # Parse base URL
        parsed_url = urlparse(config.target_url)
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
            verify=False, # enable in production
        )

        # Create Hyper Solutions API session (async)
        self.hyper_api = HyperSession(config.api_key)

        # Internal state
        self.ip: str = ""
        self.page_html: str = ""
        self.sbsd_info: Optional[SbsdInfo] = None
        self.sbsd_script: str = ""
        self.sensor_script: str = ""
        self.sensor_endpoint: str = ""
        self.sensor_context: str = ""

    async def solve(self) -> bool:
        """
        Attempts to bypass Akamai protection and access the target page.
        Returns True if successful, False if blocked.
        """
        # Get public IP
        self.ip = await self._get_public_ip()
        print(f"Public IP: {self.ip}")

        print("Step 1: Making initial request to detect Akamai protection...")

        # Step 1: Fetch the page and detect protection type
        await self._fetch_page()

        # Step 2: Handle SBSD if detected
        if self.sbsd_info:
            print(f"Step 2: SBSD detected (hardblock={self.sbsd_info.is_hardblock()}), solving...")
            await self._solve_sbsd()
        else:
            print("Step 2: No SBSD detected, skipping...")

        # Step 3: Handle sensor flow
        print("Step 3: Starting sensor flow...")
        if not self._parse_sensor_endpoint():
            print("  Sensor endpoint not found, skipping sensor posts")
            return True

        await self._fetch_sensor_script()

        # Step 4: Submit sensors (up to 3 times)
        print("Step 4: Submitting sensors...")
        for i in range(3):
            print(f"  Sensor attempt {i + 1}/3...")
            await self._post_sensor(i)

            # Check if cookie is valid
            abck = self._get_cookie("_abck")
            if is_cookie_valid(abck, i):
                print(f"  Cookie valid after {i + 1} sensor(s)!")
                return True

        # Check final cookie state
        abck = self._get_cookie("_abck")
        if "~" not in abck:
            print("Warning: Cookie doesn't contain stopping signal (~). Site may not use stopping signal, or cookie is invalid.")

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

    async def _fetch_page(self) -> None:
        """Makes a GET request to the target page and extracts protection info."""
        headers = self._build_headers({
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=0, i",
        })

        header_order = self._build_header_order([
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
            "sec-fetch-dest", "accept-encoding", "accept-language", "priority",
        ])

        resp = await self.client.get(
            self.config.target_url,
            headers=headers,
            orig_headers=header_order,
        )
        self.page_html = await resp.text()

        # Check for SBSD
        self.sbsd_info = parse_sbsd_info(self.page_html)
        if self.sbsd_info:
            print(f"  SBSD detected: path={self.sbsd_info.path}, uuid={self.sbsd_info.uuid}, t={self.sbsd_info.t}")

    async def _solve_sbsd(self) -> None:
        """Handles the SBSD challenge flow."""
        # Fetch SBSD script
        print("  Fetching SBSD script...")
        await self._fetch_sbsd_script()

        if self.sbsd_info.is_hardblock():
            # Hardblock mode: post once, then reload page
            print("  Hardblock mode: posting single SBSD payload...")
            await self._post_sbsd(0)

            # Reload the page
            print("  Reloading page after SBSD...")
            await self._fetch_page()
        else:
            # Non-hardblock mode: post twice with index 0 and 1
            print("  Non-hardblock mode: posting two SBSD payloads...")
            await self._post_sbsd(0)
            await self._post_sbsd(1)

    async def _fetch_sbsd_script(self) -> None:
        """Retrieves the SBSD script content."""
        script_url = self.sbsd_info.script_url(self.config.target_url)

        headers = self._build_headers({
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "script",
            "referer": self.config.target_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1",
        })

        header_order = self._build_header_order([
            "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language", "cookie", "priority",
        ])

        resp = await self.client.get(
            script_url,
            headers=headers,
            orig_headers=header_order,
        )
        self.sbsd_script = await resp.text()
        print(f"  SBSD script fetched: {len(self.sbsd_script)} bytes")

    async def _post_sbsd(self, index: int) -> None:
        """Submits an SBSD payload."""
        # Get the O cookie (bm_so or sbsd_o)
        o_cookie = self._get_cookie("bm_so")
        if not o_cookie:
            o_cookie = self._get_cookie("sbsd_o")

        payload = await self.hyper_api.generate_sbsd_data(
            SbsdInput(
                index=index,
                user_agent=USER_AGENT,
                uuid=self.sbsd_info.uuid,
                page_url=self.config.target_url,
                o_cookie=o_cookie,
                script=self.sbsd_script,
                accept_language=self.config.accept_language,
                ip=self.ip,
            )
        )

        post_url = self.sbsd_info.post_url(self.config.target_url)

        # Wrap payload in JSON body
        body_json = json.dumps({"body": payload})

        parsed = urlparse(self.config.target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = self._build_headers({
            "sec-ch-ua": SEC_CH_UA,
            "content-type": "application/json",
            "sec-ch-ua-mobile": "?0",
            "user-agent": USER_AGENT,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "accept": "*/*",
            "origin": origin,
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": self.config.target_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1, i",
        })

        header_order = self._build_header_order([
            "content-length", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
            "user-agent", "sec-ch-ua-platform", "accept", "origin",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "cookie", "priority",
        ])

        await self.client.post(
            post_url,
            headers=headers,
            orig_headers=header_order,
            body=body_json,
        )
        print(f"  SBSD payload {index} submitted")

    def _parse_sensor_endpoint(self) -> bool:
        """Extracts the sensor script endpoint from page HTML."""
        try:
            script_path = parse_script_path(self.page_html)
            parsed = urlparse(self.config.target_url)
            self.sensor_endpoint = f"{parsed.scheme}://{parsed.netloc}{script_path}"
            print(f"  Sensor endpoint: {self.sensor_endpoint}")
            return True
        except Exception:
            return False

    async def _fetch_sensor_script(self) -> None:
        """Retrieves the Akamai sensor script content."""
        headers = self._build_headers({
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "user-agent": USER_AGENT,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "script",
            "referer": self.config.target_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1",
        })

        header_order = self._build_header_order([
            "sec-ch-ua", "sec-ch-ua-mobile", "user-agent", "sec-ch-ua-platform",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language", "cookie", "priority",
        ])

        resp = await self.client.get(
            self.sensor_endpoint,
            headers=headers,
            orig_headers=header_order,
        )
        self.sensor_script = await resp.text()
        print(f"  Sensor script fetched: {len(self.sensor_script)} bytes")

    async def _post_sensor(self, iteration: int) -> None:
        """Submits sensor data to the Akamai endpoint."""
        sensor_data, sensor_context = await self.hyper_api.generate_sensor_data(
            SensorInput(
                abck=self._get_cookie("_abck"),
                bmsz=self._get_cookie("bm_sz"),
                version=self.config.version,
                page_url=self.config.target_url,
                user_agent=USER_AGENT,
                script_url=self.sensor_endpoint,
                accept_language=self.config.accept_language,
                ip=self.ip,
                context=self.sensor_context,
                script=self.sensor_script if iteration == 0 else "",
            )
        )

        # Store context for subsequent requests
        self.sensor_context = sensor_context

        # Wrap sensor data in JSON
        body_json = json.dumps({"sensor_data": sensor_data})

        parsed = urlparse(self.config.target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = self._build_headers({
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "sec-ch-ua-mobile": "?0",
            "user-agent": USER_AGENT,
            "content-type": "text/plain;charset=UTF-8",
            "accept": "*/*",
            "origin": origin,
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": self.config.target_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1, i",
        })

        header_order = self._build_header_order([
            "content-length", "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile",
            "user-agent", "content-type", "accept", "origin",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "cookie", "priority",
        ])

        await self.client.post(
            self.sensor_endpoint,
            headers=headers,
            orig_headers=header_order,
            body=body_json,
        )

    def _get_cookie(self, name: str) -> str:
        """Retrieves a cookie value by name from the cookie jar."""
        parsed = urlparse(self.base_url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme

        # Split hostname into parts and try progressively shorter domains
        # e.g., for "www.example.com" try: www.example.com, example.com
        # e.g., for "api.shop.example.com" try: api.shop.example.com, shop.example.com, example.com
        # this is because rnet cookiejar doesn't support finding a cookie for www.example.com when the Set-Cookie
        # domain contains domain=.example.com (without www)
        parts = hostname.split(".")

        for i in range(len(parts)):
            if len(parts) - i < 2:
                # Need at least 2 parts for a valid domain (e.g., "example.com")
                break

            domain = ".".join(parts[i:])
            url = f"{scheme}://{domain}"
            cookie = self.cookie_jar.get(name, url)
            if cookie:
                return cookie.value

        return ""

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
    config.target_url = "https://www.delta.com/us/en"
    config.referer = "https://www.delta.com/us/en"
    config.version = "3"  # Akamai version

    # Validate API key
    if not config.api_key:
        raise SystemExit(
            "HYPER_API_KEY environment variable not set. "
            "Get your API key at https://hypersolutions.co"
        )

    # Create and run solver
    solver = AkamaiSolver(config)
    try:
        success = await solver.solve()

        if success:
            print("\n✅ Akamai bypass successful!")
            print("You can now make authenticated requests using the same session.")
        else:
            print("\n❌ Akamai bypass failed.")
            print("The IP may be blocked or additional challenges are required.")
            raise SystemExit(1)
    finally:
        await solver.close()


if __name__ == "__main__":
    asyncio.run(main())