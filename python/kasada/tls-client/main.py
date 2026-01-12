"""
Kasada Bypass Example using python-tls-client and Hyper Solutions SDK

This example demonstrates:
  - Setting up a TLS client session with Chrome browser impersonation
  - Detecting Kasada protection (429 on page vs /fp endpoint)
  - Fetching and solving ips.js challenges
  - Generating payload data (CT) and POW tokens (CD)
  - Handling BotID verification when required
  - The complete flow from initial request to successful bypass

For more information, visit: https://docs.hypersolutions.co
Join our Discord community: https://discord.gg/akamai
"""

import base64
import os
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse

import tls_client

from hyper_sdk import Session as HyperSession
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
    """Handles the complete Kasada bypass flow."""

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

        # Create tls_client session with Chrome impersonation
        self.session = tls_client.Session(
            client_identifier="chrome_133",
            random_tls_extension_order=True,
            disable_http3=True,
        )

        if config.proxy_url:
            self.session.proxies = {
                "http": config.proxy_url,
                "https": config.proxy_url,
            }

        # Create Hyper Solutions API session
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

    def solve(self) -> bool:
        """
        Attempts to bypass Kasada protection and access the target page.
        Returns True if successful, False if blocked.
        """
        # Get public IP
        self.ip = self._get_public_ip()
        print(f"Public IP: {self.ip}")

        print("Step 1: Making initial request to detect Kasada protection...")

        # Step 1: Fetch the page and check for 429
        status_code, page_body = self._fetch_page()

        if status_code == 429:
            # Flow 1: 429 on page URL - solve and reload
            print("Step 2: Detected 429 on page, solving Kasada challenge...")
            self._solve_from_block_page(page_body)

            # Reload page
            print("Step 3: Reloading page after solving...")
            status_code, _ = self._fetch_page()

            if status_code != 200:
                print(f"Failed! Page still returning {status_code} after solve")
                return False

            print("  Page loaded successfully!")
        else:
            # Flow 2: No 429 on page - solve via /fp endpoint
            print("Step 2: No 429 on page, solving via /fp endpoint...")
            self._solve_from_fp_endpoint()

        # Step 4: Handle BotID if enabled
        if self.config.botid_enabled:
            print("Step 4: Solving BotID challenge...")
            self._solve_botid()
        else:
            print("Step 4: BotID disabled, skipping...")

        # Step 5: Generate POW (x-kpsdk-cd) for demonstration
        print("Step 5: Generating POW (x-kpsdk-cd) for API requests...")
        self._generate_pow()

        print("\n✅ Kasada bypass successful!")
        return True

    def _get_public_ip(self) -> str:
        """Retrieves the client's public IP address."""
        resp = self.session.get("https://api.ipify.org")
        return resp.text.strip()

    def _fetch_page(self) -> Tuple[int, str]:
        """Makes a GET request to the page URL."""
        headers = {
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
        }

        self.session.headers = headers
        self.session.header_order = [
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
            "sec-fetch-dest", "accept-encoding", "accept-language", "cookie", "priority",
        ]

        resp = self.session.get(self.config.page_url)
        print(f"  Page response: {resp.status_code}")

        return resp.status_code, resp.text

    def _solve_from_block_page(self, block_page_body: str) -> None:
        """Handles the flow when page returns 429."""
        # Extract ips.js URL from block page
        ips_path = parse_script_path(block_page_body)
        self.ips_link = self.base_url + ips_path
        print(f"  IPS script URL: {self.ips_link}")

        # Fetch ips.js script
        self._fetch_ips_script()

        # Generate and submit payload
        self._solve_challenge()

    def _solve_from_fp_endpoint(self) -> None:
        """Handles the flow when page doesn't return 429."""
        # Request /fp endpoint to trigger 429
        fp_url = f"{self.base_url}{KASADA_BASE_PATH}/fp?x-kpsdk-v={KASADA_VERSION}"

        headers = {
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "iframe",
            "referer": self.config.page_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=0, i",
        }

        self.session.headers = headers
        self.session.header_order = [
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language", "cookie", "priority",
        ]

        resp = self.session.get(fp_url)

        if resp.status_code != 429:
            raise Exception(f"/fp returned unexpected status code: {resp.status_code}")

        print("  /fp returned 429, extracting script...")

        # Extract ips.js URL
        ips_path = parse_script_path(resp.text)
        self.ips_link = self.base_url + ips_path
        print(f"  IPS script URL: {self.ips_link}")

        # Fetch ips.js script
        self._fetch_ips_script()

        # Generate and submit payload
        self._solve_challenge()

    def _fetch_ips_script(self) -> None:
        """Retrieves the ips.js script content."""
        headers = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "script",
            "referer": self.config.page_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1",
        }

        self.session.headers = headers
        self.session.header_order = [
            "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language", "cookie", "priority",
        ]

        resp = self.session.get(self.ips_link)

        if resp.status_code != 200:
            raise Exception(f"ips.js request returned {resp.status_code}")

        self.ips_script = resp.text
        print(f"  IPS script fetched: {len(self.ips_script)} bytes")

    def _solve_challenge(self) -> None:
        """Generates payload and submits to /tl endpoint."""
        print("  Generating Kasada payload via Hyper API...")

        # Generate payload
        payload_b64, headers_dict = self.hyper_api.generate_kasada_payload(
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

        req_headers = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "user-agent": USER_AGENT,
            "content-type": "application/octet-stream",
            "accept": "*/*",
            "origin": self.base_url,
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": self.config.page_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1, i",
        }

        # Build header order with Kasada headers at the front
        header_order = ["content-length"]

        # Add Kasada headers from payload generation
        for key, value in headers_dict.items():
            if value:
                req_headers[key] = value
                header_order.append(key)

        header_order.extend([
            "sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile",
            "user-agent", "content-type", "accept", "origin",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language", "cookie", "priority",
        ])

        self.session.headers = req_headers
        self.session.header_order = header_order

        resp = self.session.post(tl_url, data=payload)

        if resp.status_code != 200:
            raise Exception(f"/tl returned {resp.status_code}")

        # Check for reload:true
        tl_response = resp.json()

        if not tl_response.get("reload"):
            raise Exception("/tl did not return reload:true")

        print("  /tl returned reload:true - challenge solved!")

        # Store headers for POW generation
        self.tl_ct = resp.headers.get("x-kpsdk-ct", "")
        st_str = resp.headers.get("x-kpsdk-st", "")
        if st_str:
            self.tl_st = int(st_str)

        # Log response headers
        print("\n  Response headers from /tl:")
        print(f"    x-kpsdk-ct: {self.tl_ct}")
        print(f"    x-kpsdk-st: {self.tl_st}")

    def _solve_botid(self) -> None:
        """Handles the BotID/Vercel verification."""
        # Fetch BotID script
        botid_url = f"{self.base_url}{KASADA_BASE_PATH}/a-4-a/c.js?i=0&v=3&h={self.domain}"

        headers = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "script",
            "referer": self.config.page_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        }

        self.session.headers = headers
        self.session.header_order = [
            "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language","cookie", 
        ]

        resp = self.session.get(botid_url)

        if resp.status_code != 200:
            raise Exception(f"BotID script request returned {resp.status_code}")

        print(f"  BotID script fetched: {len(resp.text)} bytes")

        # Generate BotID header
        is_human_header = self.hyper_api.generate_botid_header(
            BotIDHeaderInput(
                script=resp.text,
                user_agent=USER_AGENT,
                ip=self.ip,
                accept_language=self.config.accept_language,
            )
        )

        print(f"  x-is-human header generated: {is_human_header[:50]}...")

    def _generate_pow(self) -> None:
        """Generates the x-kpsdk-cd header for protected API requests."""
        # First, make /mfc request to get fc and h headers
        print("  Making /mfc request...")

        mfc_url = f"{self.base_url}{KASADA_BASE_PATH}/mfc"

        headers = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "x-kpsdk-h": "01",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "x-kpsdk-v": KASADA_VERSION,
            "user-agent": USER_AGENT,
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": self.config.page_url,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1, i",
        }

        self.session.headers = headers
        self.session.header_order = [
            "sec-ch-ua-platform", "x-kpsdk-h", "sec-ch-ua", "sec-ch-ua-mobile",
            "x-kpsdk-v", "user-agent", "accept", "sec-fetch-site",
            "sec-fetch-mode", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "cookie", "priority",
        ]

        resp = self.session.get(mfc_url)

        self.mfc_fc = resp.headers.get("x-kpsdk-fc", "")
        self.mfc_h = resp.headers.get("x-kpsdk-h", "")

        print(f"  /mfc headers - x-kpsdk-fc: {self.mfc_fc[:30]}..., x-kpsdk-h: {self.mfc_h}")

        # Generate POW
        print("  Generating x-kpsdk-cd via Hyper API...")

        cd = self.hyper_api.generate_kasada_pow(
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

    def close(self) -> None:
        """Releases resources associated with the solver."""
        if self.hyper_api:
            self.hyper_api.close()


# =============================================================================
# MAIN FUNCTION
# =============================================================================

def main():
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
        success = solver.solve()

        if success:
            print("\nYou can now make authenticated requests using the same session.")
            print(
                "Remember to include x-kpsdk-ct, x-kpsdk-cd, x-kpsdk-h, and x-kpsdk-v headers on protected API requests.")
        else:
            print("\n❌ Kasada bypass failed.")
            print("The IP may be blocked or additional challenges are required.")
            raise SystemExit(1)
    finally:
        solver.close()


if __name__ == "__main__":
    main()