"""
DataDome Bypass Example using rnet TLS client and Hyper Solutions SDK (Async)

This example demonstrates:
  - Setting up an async TLS client session with Chrome browser impersonation
  - Detecting DataDome protection (interstitial vs slider captcha)
  - Solving interstitial challenges
  - Solving slider captcha challenges
  - Solving tags challenges (signal collection)
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
from hyper_sdk import DataDomeInterstitialInput, DataDomeSliderInput, DataDomeTagsInput
from hyper_sdk.datadome import parse_interstitial_device_check_link, parse_slider_device_check_link


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class Config:
    """Configuration for the DataDome bypass example."""

    # APIKey is your Hyper Solutions API key.
    # Get yours at: https://hypersolutions.co
    api_key: str

    # TargetURL is the protected page you want to access.
    target_url: str

    # Referer is the HTTP referer header value.
    # Usually the base domain of the target site.
    referer: str

    # CookieDomain is the domain for storing the DataDome cookie.
    # Should match the target site's domain.
    cookie_domain: str

    # AcceptLanguage is the browser's accept-language header.
    accept_language: str = "en-US,en;q=0.9"

    # ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
    proxy_url: Optional[str] = None

    # Timeout is the HTTP request timeout in seconds.
    timeout: int = 30

    # ==========================================================================
    # TAGS CONFIGURATION (for signal collection)
    # ==========================================================================

    # TagsEnabled enables DataDome tags/signal collection after solving challenges.
    tags_enabled: bool = False

    # TagsDDK is the DataDome key for the target site.
    tags_ddk: str = ""

    # TagsVersion is the DataDome tags version.
    tags_version: str = ""

    # TagsEndpoint is the DataDome tags collection endpoint.
    tags_endpoint: str = "https://datadome.example.com/js/"


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
# DATADOME SOLVER
# =============================================================================

class DataDomeSolver:
    """Handles the complete DataDome bypass flow using async rnet client."""

    def __init__(self, config: Config):
        if not config.api_key:
            raise ValueError("API key is required - get yours at https://hypersolutions.co")
        if not config.target_url:
            raise ValueError("Target URL is required")

        # Validate tags configuration if enabled
        if config.tags_enabled:
            if not config.tags_ddk:
                raise ValueError("tags_ddk is required when tags_enabled is True")
            if not config.tags_version:
                raise ValueError("tags_version is required when tags_enabled is True")

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
        self.device_check_link: str = ""
        self.html: str = ""
        self.captcha_path: str = ""
        self.is_interstitial: bool = False

    async def solve(self) -> bool:
        """
        Attempts to bypass DataDome protection and access the target page.
        Returns True if successful, False if blocked.
        """
        # Get public IP
        self.ip = await self._get_public_ip()
        print(f"Public IP: {self.ip}")

        print("Step 1: Making initial request to detect DataDome protection...")

        # Step 1: Make initial request to trigger DataDome
        await self._make_initial_request()

        # Step 2: Handle interstitial challenge if detected
        if self.is_interstitial:
            print("Step 2: Detected interstitial challenge, solving...")
            await self._solve_interstitial()

            # After interstitial, reload the page to check if we need slider or are done
            print("  Reloading page after interstitial...")
            await self._reload_page()

        # Step 3: Handle slider captcha if needed (either directly or after interstitial)
        if not self.is_interstitial and self.device_check_link:
            print("Step 3: Detected slider captcha, solving...")
            await self._solve_slider_captcha()

            # After slider, reload the page
            print("  Reloading page after slider...")
            await self._reload_page()

        # Step 4: Solve tags if enabled (signal collection for improved success rate)
        if self.config.tags_enabled:
            print("Step 4: Solving tags (signal collection)...")
            await self._solve_tags()

        # Step 5: Verify access to protected page
        print("Step 5: Verifying access to protected page...")
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

    def _get_datadome_cookie(self) -> str:
        """Retrieves the current DataDome cookie value."""
        return self._get_cookie("datadome", self.config.target_url)

    def _set_datadome_cookie(self, cookie_header: str) -> None:
        """Updates the DataDome cookie from a Set-Cookie header value."""
        # Parse cookie from Set-Cookie header format
        # Example: "datadome=abc123; Domain=.example.com; ..."
        parsed = urlparse(self.config.cookie_domain)
        domain = parsed.netloc

        # Extract just the cookie value
        if "datadome=" in cookie_header:
            # Extract value before first semicolon
            parts = cookie_header.split(";")[0]
            if "=" in parts:
                value = parts.split("=", 1)[1]

                # Remove old cookie first by setting it with the various domain variations
                # Then add the new one
                cookie = Cookie(
                    name="datadome",
                    value=value,
                    domain=domain,
                    path="/",
                )
                self.cookie_jar.add_cookie(cookie, self.config.cookie_domain)

    async def _make_initial_request(self) -> None:
        """Makes the first request to the target page to trigger DataDome."""
        headers = self._build_headers({
            "connection": "keep-alive",
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
        })

        header_order = self._build_header_order([
            "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
            "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language",
        ])

        resp = await self.client.get(
            self.config.target_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        body = await resp.text()

        # Get the DataDome cookie value
        dd_cookie = self._get_datadome_cookie()
        if not dd_cookie:
            raise Exception("DataDome cookie not found - site may not be protected or IP may be blocked")

        print(f"  DataDome cookie obtained: {dd_cookie[:20]}...")

        # Detect challenge type and parse device check link
        if "https://ct.captcha-delivery.com/i.js" in body:
            # Interstitial challenge detected
            self.is_interstitial = True
            self.device_check_link = parse_interstitial_device_check_link(
                body,
                dd_cookie,
                self.config.target_url,
            )
            print("  Challenge type: Interstitial")
        else:
            # Slider captcha challenge
            self.is_interstitial = False
            self.device_check_link = parse_slider_device_check_link(
                body,
                dd_cookie,
                self.config.target_url,
            )
            print("  Challenge type: Slider Captcha")

    async def _reload_page(self) -> None:
        """Reloads the target page after solving a challenge."""
        headers = self._build_headers({
            "connection": "keep-alive",
            "cache-control": "max-age=0",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "referer": self.config.target_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        })

        header_order = self._build_header_order([
            "host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
            "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language",
        ])

        resp = await self.client.get(
            self.config.target_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        body = await resp.text()

        # Check if we got another challenge (slider after interstitial)
        dd_cookie = self._get_datadome_cookie()

        if "captcha-delivery.com" in body:
            # Another challenge detected - parse the device check link
            try:
                self.device_check_link = parse_slider_device_check_link(
                    body,
                    dd_cookie,
                    self.config.target_url,
                )
                self.is_interstitial = False
                print("  Additional slider challenge detected after reload")
            except Exception:
                # Try interstitial
                try:
                    self.device_check_link = parse_interstitial_device_check_link(
                        body,
                        dd_cookie,
                        self.config.target_url,
                    )
                    self.is_interstitial = True
                    print("  Additional interstitial challenge detected after reload")
                except Exception:
                    # No challenge found, we're good
                    self.device_check_link = ""
        else:
            # No challenge, clear the device check link
            self.device_check_link = ""

    async def _solve_interstitial(self) -> None:
        """Handles the interstitial challenge flow."""
        # Step 2a: Fetch the interstitial page
        print("  Fetching interstitial page...")
        await self._fetch_interstitial_page()

        # Step 2b: Generate interstitial payload using Hyper API
        print("  Generating interstitial payload via Hyper API...")
        result = await self.hyper_api.generate_interstitial_payload(
            DataDomeInterstitialInput(
                user_agent=USER_AGENT,
                device_link=self.device_check_link,
                html=self.html,
                ip=self.ip,
                accept_language=self.config.accept_language,
            )
        )
        payload = result["payload"]

        # Step 2c: Submit the interstitial payload
        print("  Submitting interstitial solution...")
        await self._submit_interstitial(payload)

    async def _fetch_interstitial_page(self) -> None:
        """Retrieves the interstitial challenge HTML."""
        headers = self._build_headers({
            "Connection": "keep-alive",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "iframe",
            "Sec-Fetch-Storage-Access": "none",
            "Referer": self.config.referer,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
        })

        header_order = self._build_header_order([
            "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
            "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Storage-Access", "Referer",
            "Accept-Encoding", "Accept-Language",
        ])

        resp = await self.client.get(
            self.device_check_link,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        self.html = await resp.text()

    async def _submit_interstitial(self, payload: str) -> None:
        """Posts the generated payload to solve the interstitial."""
        headers = self._build_headers({
            "Connection": "keep-alive",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "User-Agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "sec-ch-ua-mobile": "?0",
            "Accept": "*/*",
            "Origin": "https://geo.captcha-delivery.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Storage-Access": "none",
            "Referer": self.device_check_link,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": self.config.accept_language,
        })

        header_order = self._build_header_order([
            "Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent",
            "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Accept", "Origin",
            "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Storage-Access",
            "Referer", "Accept-Encoding", "Accept-Language",
        ])

        resp = await self.client.post(
            "https://geo.captcha-delivery.com/interstitial/",
            headers=headers,
            orig_headers=header_order,
            body=payload,
            default_headers=False,
        )

        # Parse the response
        result = await resp.json()

        # Store the new cookie
        if result.get("cookie"):
            self._set_datadome_cookie(result["cookie"])

        print(f"  Interstitial result: view={result.get('view', 'unknown')}")

        # Mark that we're no longer in interstitial mode
        self.is_interstitial = False
        self.device_check_link = ""

    async def _solve_slider_captcha(self) -> None:
        """Handles the slider captcha challenge flow."""
        # Step 3a: Fetch the captcha page
        print("  Fetching captcha page...")
        await self._fetch_captcha_page()

        # Step 3b: Download puzzle images
        print("  Downloading puzzle images...")
        puzzle = await self._download_puzzle_image()
        piece = await self._download_piece_image()

        # Step 3c: Generate slider solution using Hyper API
        print("  Generating slider solution via Hyper API...")
        result = await self.hyper_api.generate_slider_payload(
            DataDomeSliderInput(
                user_agent=USER_AGENT,
                device_link=self.device_check_link,
                html=self.html,
                puzzle=puzzle,
                piece=piece,
                ip=self.ip,
                accept_language=self.config.accept_language,
                parent_url=""
            )
        )
        check_url = result["payload"]

        # Step 3d: Submit the slider solution
        print("  Submitting slider solution...")
        await self._submit_slider_solution(check_url)

    async def _fetch_captcha_page(self) -> None:
        """Retrieves the slider captcha HTML."""
        headers = self._build_headers({
            "connection": "keep-alive",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "iframe",
            "sec-fetch-storage-access": "none",
            "referer": self.config.referer,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        })

        header_order = self._build_header_order([
            "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
            "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-storage-access", "referer",
            "accept-encoding", "accept-language",
        ])

        resp = await self.client.get(
            self.device_check_link,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        self.html = await resp.text()

        # Extract the captcha challenge path from the HTML
        match = re.search(r"captchaChallengePath:\s*'(.*?)'", self.html)
        if not match:
            raise Exception("Captcha challenge path not found in HTML")

        self.captcha_path = match.group(1)
        print(f"  Captcha path: {self.captcha_path}")

    async def _download_puzzle_image(self) -> str:
        """Downloads the main puzzle background image and returns as string."""
        headers = self._build_headers({
            "origin": "https://geo.captcha-delivery.com",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "image",
            "referer": "https://geo.captcha-delivery.com/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "i",
        })

        header_order = self._build_header_order([
            "origin", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "priority",
        ])

        resp = await self.client.get(
            self.captcha_path,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        content = await resp.bytes()
        return content.decode("latin-1")

    async def _download_piece_image(self) -> str:
        """Downloads the slider piece image and returns as string."""
        # The piece image URL is derived from the puzzle URL by replacing .jpg with .frag.png
        piece_url = self.captcha_path.replace(".jpg", ".frag.png")

        headers = self._build_headers({
            "origin": "https://geo.captcha-delivery.com",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "image",
            "referer": "https://geo.captcha-delivery.com/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "i",
        })

        header_order = self._build_header_order([
            "origin", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "priority",
        ])

        resp = await self.client.get(
            piece_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )
        content = await resp.bytes()
        return content.decode("latin-1")

    async def _submit_slider_solution(self, check_url: str) -> None:
        """Submits the generated slider solution."""
        headers = self._build_headers({
            "connection": "keep-alive",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "sec-fetch-storage-access": "none",
            "referer": self.device_check_link,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        })

        header_order = self._build_header_order([
            "host", "connection", "sec-ch-ua-platform", "user-agent", "sec-ch-ua",
            "content-type", "sec-ch-ua-mobile", "accept", "sec-fetch-site",
            "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-storage-access", "referer",
            "accept-encoding", "accept-language",
        ])

        resp = await self.client.get(
            check_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )

        # Check for block (HTTP 403 means failed verification)
        if resp.status.as_int() == 403:
            raise Exception("Slider solution was rejected - captcha verification failed")

        # Parse the response to get the new cookie
        result = await resp.json()

        # Store the new cookie
        if result.get("cookie"):
            self._set_datadome_cookie(result["cookie"])
            print("  Slider captcha solved successfully!")

        # Clear device check link since we've solved the captcha
        self.device_check_link = ""

    async def _solve_tags(self) -> None:
        """Handles the DataDome tags/signal collection flow."""
        # Get current DataDome cookie
        cid = self._get_datadome_cookie()
        if not cid:
            raise Exception("DataDome cookie not found for tags")

        # ==========================================================================
        # First tags request: "ch" (challenge) type
        # ==========================================================================
        print("  Sending first tags request (type: ch)...")
        ch_payload = await self.hyper_api.generate_tags_payload(
            DataDomeTagsInput(
                user_agent=USER_AGENT,
                cid=cid,
                ddk=self.config.tags_ddk,
                referer=self.config.referer,
                tags_type="ch",
                ip=self.ip,
                version=self.config.tags_version,
                accept_language=self.config.accept_language,
            )
        )

        await self._post_tags(ch_payload)

        # ==========================================================================
        # Sleep between requests to simulate real user behavior
        # ==========================================================================
        print("  Waiting 5 seconds before second tags request...")
        await asyncio.sleep(5)

        # ==========================================================================
        # Second tags request: "le" (loaded events) type
        # Refresh the cookie as it may have been updated
        # ==========================================================================
        cid = self._get_datadome_cookie()

        print("  Sending second tags request (type: le)...")
        le_payload = await self.hyper_api.generate_tags_payload(
            DataDomeTagsInput(
                user_agent=USER_AGENT,
                cid=cid,
                ddk=self.config.tags_ddk,
                referer=self.config.referer,
                tags_type="le",
                ip=self.ip,
                version=self.config.tags_version,
                accept_language=self.config.accept_language,
            )
        )

        await self._post_tags(le_payload)

        print("  Tags solved successfully!")

    async def _post_tags(self, payload: str) -> None:
        """Sends a tags payload to the DataDome tags endpoint."""
        # Extract origin from referer for the Origin header
        parsed = urlparse(self.config.referer)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = self._build_headers({
            "sec-ch-ua": SEC_CH_UA,
            "content-type": "application/x-www-form-urlencoded",
            "sec-ch-ua-mobile": "?0",
            "user-agent": USER_AGENT,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "accept": "*/*",
            "origin": origin,
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": self.config.referer,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1, i",
        })

        header_order = self._build_header_order([
            "content-length", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
            "user-agent", "sec-ch-ua-platform", "accept", "origin",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "priority",
        ])

        resp = await self.client.post(
            self.config.tags_endpoint,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
            body=payload,
        )

        # Parse the response to get the updated cookie
        result = await resp.json()

        # Update cookie if provided
        if result.get("cookie"):
            self._set_datadome_cookie(result["cookie"])

    async def _verify_access(self) -> bool:
        """Makes a final request to verify we can access the protected page."""
        headers = self._build_headers({
            "cache-control": "max-age=0",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "referer": self.config.target_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=0, i",
        })

        header_order = self._build_header_order([
            "host", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
            "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "cookie", "priority",
        ])

        resp = await self.client.get(
            self.config.target_url,
            headers=headers,
            orig_headers=header_order,
            default_headers=False,
        )

        success = resp.status.as_int() != 403
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
    config.target_url = "https://tickets.example.com/"
    config.referer = "https://tickets.example.com/"
    config.cookie_domain = "https://example.com/"

    # Enable tags solving for improved success rate
    config.tags_enabled = True
    config.tags_ddk = "EXAMPLEDDK"  # Site-specific DataDome key
    config.tags_version = "5.1.13"  # DataDome tags version
    config.tags_endpoint = "https://datadome.example.com/js/"

    # Validate API key
    if not config.api_key:
        raise SystemExit(
            "HYPER_API_KEY environment variable not set. "
            "Get your API key at https://hypersolutions.co"
        )

    # Create and run solver
    solver = DataDomeSolver(config)
    try:
        success = await solver.solve()

        if success:
            print("\n✅ DataDome bypass successful!")
            print("You can now make authenticated requests using the same session.")
        else:
            print("\n❌ DataDome bypass failed.")
            print("The IP may be blocked or additional challenges are required.")
            raise SystemExit(1)
    finally:
        await solver.close()


if __name__ == "__main__":
    asyncio.run(main())