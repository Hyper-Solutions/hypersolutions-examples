"""
Incapsula Reese84 Bypass Example using python-tls-client and Hyper Solutions SDK

This example demonstrates:
  - Setting up a TLS client session with Chrome browser impersonation
  - Detecting Incapsula protection and extracting script paths
  - Fetching the Reese84 script content
  - Handling POW (Proof of Work) challenges when required
  - Generating and submitting Reese84 sensors via the Hyper API
  - Handling the complete flow from initial request to successful bypass

For more information, visit: https://docs.hypersolutions.co
Join our Discord community: https://discord.gg/akamai
"""

import json
import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import tls_client

from hyper_sdk import Session as HyperSession
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
    """Handles the complete Incapsula Reese84 bypass flow."""

    def __init__(self, config: Config):
        if not config.api_key:
            raise ValueError("API key is required - get yours at https://hypersolutions.co")
        if not config.target_url:
            raise ValueError("Target URL is required")

        self.config = config

        # Parse base URL
        parsed_url = urlparse(config.target_url)
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
        self.path: str = ""  # Script path for sensor POST endpoint (e.g., /abc123/def456)
        self.full_path: str = ""  # Full script path with query params for fetching
        self.script: str = ""  # Full Reese84 script content

    def solve(self) -> bool:
        """
        Attempts to bypass Incapsula Reese84 protection and access the target page.
        Returns True if successful, False if blocked.
        """
        # Get public IP
        self.ip = self._get_public_ip()
        print(f"Public IP: {self.ip}")

        print("Step 1: Making initial request to detect Incapsula protection...")

        # Step 1: Make initial request to trigger Incapsula and extract script paths
        self._make_initial_request()

        # Step 2: Fetch the Reese84 script content
        print("Step 2: Fetching Reese84 script...")
        self._fetch_script()

        # Step 3: Get POW challenge if enabled
        pow_value = ""
        if self.config.pow_enabled:
            print("Step 3: Fetching POW challenge...")
            pow_value = self._get_pow()
            print(f"  POW obtained: {pow_value[:30]}...")
        else:
            print("Step 3: POW disabled, skipping...")

        # Step 4: Generate sensor via Hyper API
        print("Step 4: Generating Reese84 sensor via Hyper API...")
        sensor = self._generate_sensor(pow_value)
        print(f"  Sensor generated: {sensor[:50]}...")

        # Step 5: Submit the sensor
        print("Step 5: Submitting sensor...")
        self._submit_sensor(sensor)

        # Step 6: Verify access to protected page
        print("Step 6: Verifying access to protected page...")
        return self._verify_access()

    def _get_public_ip(self) -> str:
        """Retrieves the client's public IP address."""
        resp = self.session.get("https://api.ipify.org")
        return resp.text.strip()

    def _make_initial_request(self) -> None:
        """Makes the first request to the target page to trigger Incapsula."""
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
            "sec-fetch-dest", "accept-encoding", "accept-language", "priority",
        ]

        resp = self.session.get(self.config.target_url)
        body = resp.text

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

    def _fetch_script(self) -> None:
        """Retrieves the Reese84 script content."""
        parsed = urlparse(self.config.target_url)
        script_url = f"{parsed.scheme}://{parsed.netloc}{self.full_path}"

        headers = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "script",
            "referer": self.config.referer,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
        }

        self.session.headers = headers
        self.session.header_order = [
            "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
            "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language",
        ]

        resp = self.session.get(script_url)
        self.script = resp.text
        print(f"  Script fetched: {len(self.script)} bytes")

    def _get_pow(self) -> str:
        """Fetches the POW (Proof of Work) challenge from the server."""
        parsed = urlparse(self.config.target_url)
        pow_url = f"{parsed.scheme}://{parsed.netloc}{self.path}?d={parsed.netloc}"

        # POW request body is hardcoded
        pow_body = '{"f":"gpc"}'

        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "pragma": "no-cache",
            "cache-control": "no-cache",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "accept": "application/json; charset=utf-8",
            "sec-ch-ua": SEC_CH_UA,
            "content-type": "text/plain; charset=utf-8",
            "sec-ch-ua-mobile": "?0",
            "origin": origin,
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": self.config.referer,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1, i",
        }

        self.session.headers = headers
        self.session.header_order = [
            "content-length", "pragma", "cache-control", "sec-ch-ua-platform",
            "user-agent", "accept", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
            "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
            "referer", "accept-encoding", "accept-language", "priority",
        ]

        resp = self.session.post(pow_url, data=pow_body)

        # Response is a JSON string
        return resp.json()

    def _generate_sensor(self, pow_value: str) -> str:
        """Calls the Hyper API to generate a Reese84 sensor."""
        parsed = urlparse(self.config.target_url)
        script_url = f"{parsed.scheme}://{parsed.netloc}{self.full_path}"

        sensor = self.hyper_api.generate_reese84_sensor(
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

    def _submit_sensor(self, sensor: str) -> None:
        """Posts the generated sensor to the Incapsula endpoint."""
        parsed = urlparse(self.config.target_url)
        sensor_url = f"{parsed.scheme}://{parsed.netloc}{self.path}?d={parsed.netloc}"
        origin = f"{parsed.scheme}://{parsed.netloc}"

        headers = {
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "user-agent": USER_AGENT,
            "accept": "application/json; charset=utf-8",
            "sec-ch-ua": SEC_CH_UA,
            "content-type": "text/plain; charset=utf-8",
            "sec-ch-ua-mobile": "?0",
            "origin": origin,
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": self.config.referer,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=1, i",
        }

        self.session.headers = headers
        self.session.header_order = [
            "content-length", "sec-ch-ua-platform", "user-agent", "accept",
            "sec-ch-ua", "content-type", "sec-ch-ua-mobile", "origin",
            "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
            "accept-encoding", "accept-language", "cookie", "priority",
        ]

        resp = self.session.post(sensor_url, data=sensor)

        # Parse response to get the token
        result = resp.json()

        token = result.get("token", "")
        cookie_domain = result.get("cookieDomain", "")

        if not token:
            raise Exception("No token received in sensor response")

        # Set the reese84 cookie
        self.session.add_cookies_to_session(sensor_url, [
            {
                "domain": cookie_domain,
                "path": "/",
                "name": "reese84",
                "value": token,
            }
        ])

        print(f"  Token received and cookie set: {token[:30]}...")

    def _verify_access(self) -> bool:
        """Makes a final request to verify we can access the protected page."""
        headers = {
            "cache-control": "max-age=0",
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "referer": self.config.referer,
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.config.accept_language,
            "priority": "u=0, i",
        }

        self.session.headers = headers
        self.session.header_order = [
            "cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
            "sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding",
            "accept-language", "cookie", "priority",
        ]

        resp = self.session.get(self.config.target_url)
        body = resp.text

        # Check if we're still seeing the challenge page
        if "Pardon Our Interruption" in body:
            print(f"Failed! Still seeing challenge page (HTTP {resp.status_code})")
            return False

        success = resp.status_code == 200
        if success:
            print(f"Success! Access granted (HTTP {resp.status_code})")
        else:
            print(f"Failed! Access denied (HTTP {resp.status_code})")

        return success

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
        success = solver.solve()

        if success:
            print("\n✅ Incapsula Reese84 bypass successful!")
            print("You can now make authenticated requests using the same session.")
        else:
            print("\n❌ Incapsula Reese84 bypass failed.")
            print("The IP may be blocked or additional challenges are required.")
            raise SystemExit(1)
    finally:
        solver.close()


if __name__ == "__main__":
    main()