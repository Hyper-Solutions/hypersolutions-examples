"""
Incapsula Reese84 Bypass Example using rnet TLS client and Hyper Solutions SDK (Async)

This example demonstrates:
  - Setting up an async TLS client session with Chrome browser impersonation
  - Detecting Incapsula protection and extracting script paths
  - Fetching the Reese84 script content
  - Handling POW (Proof of Work) challenges when required
  - Generating and submitting Reese84 sensors via the Hyper API
  - Handling the complete flow from initial request to successful bypass

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

from rnet import Client, Proxy, HeaderMap, OrigHeaderMap, Jar, Cookie
from rnet.emulation import Emulation

from hyper_sdk import SessionAsync as HyperSession
from hyper_sdk import ReeseInput


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class Config:
    """Configuration for the Incapsula Reese84 bypass example."""

    # APIKey is your Hyper Solutions API key.
    # Get yours at: https://hypersolutions.co
    api_key: str

    # TargetURL is the protected page you want to access.
    target_url: str

    # Referer is the HTTP referer header value.
    # Usually the base domain of the target site.
    referer: str

    # CookieDomain is the domain for storing the Reese84 cookie.
    # Should match the target site's domain.
    cookie_domain: str

    # AcceptLanguage is the browser's accept-language header.
    accept_language: str = "en-US,en;q=0.9"

    # ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
    proxy_url: Optional[str] = None

    # Timeout is the HTTP request timeout in seconds.
    timeout: int = 30

    # PowEnabled enables POW challenge solving.
    # Some sites require an additional POW step before sensor submission.
    pow_enabled: bool = False


def default_config() -> Config:
    """Returns a sensible default configuration."""
    return Config(
        api_key=os.environ.get("HYPER_API_KEY", ""),
        target_url="https://example.com/protected-page",
        referer="https://example.com/",
        cookie_domain="https://example.com/",
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


# =============================================================================
# INCAPSULA REESE84 SOLVER
# =============================================================================

class Reese84Solver:
    """Handles the complete Incapsula Reese84 bypass flow using async rnet client."""

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
            verify=False,  # Enable in production
        )

        # Create Hyper Solutions API session (async)
        self.hyper_api = HyperSession(config.api_key)

        # Internal state
        self.ip: str = ""
        self.path: str = ""  # Script path for sensor POST endpoint (e.g., /abc123/def456)
        self.full_path: str = ""  # Full script path with query params for fetching
        self.script: str = ""  # Full Reese84 script content

    async def solve(self) -> bool:
        """
        Attempts to bypass Incapsula Reese84 protection and access the target page.
        Returns True if successful, False if blocked.
        """
        # Get public IP
        self.ip = await self._get_public_ip()
        print(f"Public IP: {self.ip}")

        print("Step 1: Making initial request to detect Incapsula protection...")

        # Step 1: Make initial request to trigger Incapsula and extract script paths
        await self._make_initial_request()

        # Step 2: Fetch the Reese84 script content
        print("Step 2: Fetching Reese84 script...")
        await self._fetch_script()

        # Step 3: Get POW challenge if enabled
        pow_value = ""
        if self.config.pow_enabled:
            print("Step 3: Fetching POW challenge...")
            pow_value = await self._get_pow()
            print(f"  POW obtained: {pow_value[:30]}...")
        else:
            print("Step 3: POW disabled, skipping...")

        # Step 4: Generate sensor via Hyper API
        print("Step 4: Generating Reese84 sensor via Hyper API...")
        sensor = await self._generate_sensor(pow_value)
        print(f"  Sensor generated: {sensor[:50]}...")

        # Step 5: Submit the sensor
        print("Step 5: Submitting sensor...")
        await self._submit_sensor(sensor)

        # Step 6: Verify access to protected page
        print("Step 6: Verifying access to protected page...")
        return await self._verify_access()

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
        self.cookie_jar.add_cookie(cookie, url)

    async def _make_initial_request(self) -> None:
        """Makes the first request to the target page to trigger Incapsula."""
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
            "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language", "Priority",
        ])

        resp = await self.client.get(
            self.config.target_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        body = await resp.text()

        # Check for Incapsula challenge page
        if "Pardon Our Interruption" not in body:
            raise Exception("Incapsula challenge not detected - site may not be protected or IP may be blocked")

        print("  Incapsula challenge detected!")

        # Extract script path for sensor POST endpoint
        # Pattern: src="/abc123/def456?..."
        path_regex = re.compile(r'src\s*=\s*"(/[^/]+/[^?]+)\?.*"')
        matches = path_regex.search(body)
        if not matches:
            raise Exception("Failed to extract script path from challenge page")
        self.path = matches.group(1)
        print(f"  Script path: {self.path}")

        # Extract full script path with query params for fetching
        # Pattern: scriptElement.src = "/abc123/def456?d=example.com&..."
        full_path_regex = re.compile(r'scriptElement\.src\s*=\s*"(.*?)"')
        matches = full_path_regex.search(body)
        if not matches:
            raise Exception("Failed to extract full script path from challenge page")
        self.full_path = matches.group(1)
        print(f"  Full script path: {self.full_path}")

    async def _fetch_script(self) -> None:
        """Retrieves the Reese84 script content."""
        parsed = urlparse(self.config.target_url)
        script_url = f"{parsed.scheme}://{parsed.netloc}{self.full_path}"

        headers = self._build_headers({
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "User-Agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "Accept": "*/*",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Dest": "script",
            "Referer": self.config.referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
        })

        header_order = self._build_header_order([
            "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
            "Referer", "Accept-Encoding", "Accept-Language",
        ])

        resp = await self.client.get(
            script_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        self.script = await resp.text()
        print(f"  Script fetched: {len(self.script)} bytes")

    async def _get_pow(self) -> str:
        """Fetches the POW (Proof of Work) challenge from the server."""
        parsed = urlparse(self.config.target_url)
        pow_url = f"{parsed.scheme}://{parsed.netloc}{self.path}?d={parsed.netloc}"

        # POW request body is hardcoded
        pow_body = '{"f":"gpc"}'

        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = self._build_headers({
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "User-Agent": USER_AGENT,
            "Accept": "application/json; charset=utf-8",
            "sec-ch-ua": SEC_CH_UA,
            "Content-Type": "text/plain; charset=utf-8",
            "sec-ch-ua-mobile": "?0",
            "Origin": origin,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": self.config.referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=1, i",
        })

        header_order = self._build_header_order([
            "Content-Length", "Pragma", "Cache-Control", "sec-ch-ua-platform",
            "User-Agent", "Accept", "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile",
            "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
            "Referer", "Accept-Encoding", "Accept-Language", "Priority",
        ])

        resp = await self.client.post(
            pow_url,
            headers=headers,
            orig_headers=header_order,
            body=pow_body,
            default_headers=False,
        )

        # Response is a JSON string
        result = await resp.json()
        return result

    async def _generate_sensor(self, pow_value: str) -> str:
        """Calls the Hyper API to generate a Reese84 sensor."""
        parsed = urlparse(self.config.target_url)
        script_url = f"{parsed.scheme}://{parsed.netloc}{self.full_path}"

        sensor = await self.hyper_api.generate_reese84_sensor(
            ReeseInput(
                user_agent=USER_AGENT,
                accept_language=self.config.accept_language,
                ip=self.ip,
                script_url=script_url,
                pageUrl=self.config.target_url,
                pow=pow_value,
                script=self.script,
            )
        )

        return sensor

    async def _submit_sensor(self, sensor: str) -> None:
        """Posts the generated sensor to the Incapsula endpoint."""
        parsed = urlparse(self.config.target_url)
        sensor_url = f"{parsed.scheme}://{parsed.netloc}{self.path}?d={parsed.netloc}"
        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = self._build_headers({
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "User-Agent": USER_AGENT,
            "Accept": "application/json; charset=utf-8",
            "sec-ch-ua": SEC_CH_UA,
            "Content-Type": "text/plain; charset=utf-8",
            "sec-ch-ua-mobile": "?0",
            "Origin": origin,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": self.config.referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=1, i",
        })

        header_order = self._build_header_order([
            "Content-Length", "sec-ch-ua-platform", "User-Agent", "Accept",
            "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Origin",
            "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer",
            "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
        ])

        resp = await self.client.post(
            sensor_url,
            headers=headers,
            orig_headers=header_order,
            body=sensor,
            default_headers=False,
        )

        # Parse response to get the token
        result = await resp.json()

        token = result.get("token", "")
        cookie_domain = result.get("cookieDomain", "")

        if not token:
            raise Exception("No token received in sensor response")

        # Set the reese84 cookie
        self._set_cookie("reese84", token, cookie_domain, sensor_url)

        print(f"  Token received and cookie set: {token[:30]}...")

    async def _verify_access(self) -> bool:
        """Makes a final request to verify we can access the protected page."""
        headers = self._build_headers({
            "Cache-Control": "max-age=0",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
            "Referer": self.config.referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
            "Priority": "u=0, i",
        })

        header_order = self._build_header_order([
            "Cache-Control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
            "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding",
            "Accept-Language", "Cookie", "Priority",
        ])

        resp = await self.client.get(
            self.config.target_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        body = await resp.text()

        # Check if we're still seeing the challenge page
        if "Pardon Our Interruption" in body:
            print(f"Failed! Still seeing challenge page (HTTP {resp.status.as_int()})")
            return False

        success = resp.status.as_int() == 200
        if success:
            print(f"Success! Access granted (HTTP {resp.status.as_int()})")
        else:
            print(f"Failed! Access denied (HTTP {resp.status.as_int()})")

        return success

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
    config.target_url = "https://digital.example.com/book"
    config.referer = "https://digital.example.com/"
    config.cookie_domain = "https://digital.example.com/"

    # Enable POW if required by the target site
    config.pow_enabled = False

    # Validate API key
    if not config.api_key:
        raise SystemExit(
            "HYPER_API_KEY environment variable not set. "
            "Get your API key at https://hypersolutions.co"
        )

    # Create and run solver
    solver = Reese84Solver(config)
    try:
        success = await solver.solve()

        if success:
            print("\n✅ Incapsula Reese84 bypass successful!")
            print("You can now make authenticated requests using the same session.")
        else:
            print("\n❌ Incapsula Reese84 bypass failed.")
            print("The IP may be blocked or additional challenges are required.")
            raise SystemExit(1)
    finally:
        await solver.close()


if __name__ == "__main__":
    asyncio.run(main())