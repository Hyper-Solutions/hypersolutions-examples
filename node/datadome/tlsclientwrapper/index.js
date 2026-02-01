/**
 * DataDome Bypass Example using tlsclientwrapper and Hyper Solutions SDK
 *
 * This example demonstrates:
 *   - Setting up a TLS client session with Chrome browser impersonation
 *   - Detecting DataDome protection (interstitial vs slider captcha)
 *   - Solving interstitial challenges
 *   - Solving slider captcha challenges
 *   - Solving tags challenges (signal collection)
 *   - Handling the complete flow from initial request to successful bypass
 *
 * For more information, visit: https://docs.hypersolutions.co
 * Join our Discord community: https://discord.gg/akamai
 */

import { ModuleClient, SessionClient } from 'tlsclientwrapper';
import {
    Session as HyperSession,
    InterstitialInput,
    SliderInput,
    TagsInput,
    generateInterstitialPayload,
    generateSliderPayload,
    generateTagsPayload,
    parseInterstitialDeviceCheckUrl,
    parseSliderDeviceCheckUrl,
} from 'hyper-sdk-js';

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Configuration for the DataDome bypass example.
 * @typedef {Object} Config
 * @property {string} apiKey - Your Hyper Solutions API key
 * @property {string} targetUrl - The protected page you want to access
 * @property {string} referer - The HTTP referer header value
 * @property {string} cookieDomain - The domain for storing the DataDome cookie
 * @property {string} acceptLanguage - The browser's accept-language header
 * @property {string|null} proxyUrl - Optional HTTP/HTTPS/SOCKS5 proxy
 * @property {number} timeout - HTTP request timeout in seconds
 * @property {boolean} tagsEnabled - Enable DataDome tags/signal collection
 * @property {string} tagsDdk - The DataDome key for the target site
 * @property {string} tagsVersion - The DataDome tags version
 * @property {string} tagsEndpoint - The DataDome tags collection endpoint
 */

/**
 * Returns a sensible default configuration.
 * You MUST replace the apiKey and targetUrl with your own values.
 * @returns {Config}
 */
function defaultConfig() {
    return {
        apiKey: process.env.HYPER_API_KEY || '',
        targetUrl: 'https://example.com/protected-page',
        referer: 'https://example.com/',
        cookieDomain: 'https://example.com/',
        acceptLanguage: 'en-US,en;q=0.9',
        proxyUrl: process.env.HTTP_PROXY || null,
        timeout: 30,

        // Tags configuration (disabled by default)
        tagsEnabled: false,
        tagsDdk: '',
        tagsVersion: '',
        tagsEndpoint: 'https://datadome.example.com/js/',
    };
}

// =============================================================================
// BROWSER FINGERPRINT CONSTANTS
// =============================================================================

// User agent string for Chrome on Windows
const USER_AGENT =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36';

// sec-ch-ua header value for Chrome 143
const SEC_CH_UA = '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"';

// sec-ch-ua-platform header value
const SEC_CH_UA_PLATFORM = '"Windows"';

// =============================================================================
// DATADOME SOLVER
// =============================================================================

/**
 * Handles the complete DataDome bypass flow.
 */
class DataDomeSolver {
    /**
     * @param {Config} config
     */
    constructor(config) {
        if (!config.apiKey) {
            throw new Error('API key is required - get yours at https://hypersolutions.co');
        }
        if (!config.targetUrl) {
            throw new Error('Target URL is required');
        }

        // Validate tags configuration if enabled
        if (config.tagsEnabled) {
            if (!config.tagsDdk) {
                throw new Error('tagsDdk is required when tagsEnabled is true');
            }
            if (!config.tagsVersion) {
                throw new Error('tagsVersion is required when tagsEnabled is true');
            }
        }

        this.config = config;

        // Parse base URL
        const parsedUrl = new URL(config.targetUrl);
        this.baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;

        // Create ModuleClient for worker pool management
        this.moduleClient = new ModuleClient();

        // Create TLS client session with Chrome impersonation
        const sessionOptions = {
            tlsClientIdentifier: 'chrome_133',
            randomTlsExtensionOrder: true,
            timeoutSeconds: config.timeout,
            defaultHeaders: null,
            retryIsEnabled: false,
            followRedirects: false,
        };

        if (config.proxyUrl) {
            sessionOptions.proxyUrl = config.proxyUrl;
        }

        this.session = new SessionClient(this.moduleClient, sessionOptions);

        // Create Hyper Solutions API session
        this.hyperApi = new HyperSession(config.apiKey);

        // Internal state
        this.ip = '';
        this.deviceCheckLink = '';
        this.html = '';
        this.captchaPath = '';
        this.isInterstitial = false;
    }

    /**
     * Attempts to bypass DataDome protection and access the target page.
     * @returns {Promise<boolean>} True if successful, false if blocked.
     */
    async solve() {
        // Get public IP
        this.ip = await this._getPublicIp();
        console.log(`Public IP: ${this.ip}`);

        console.log('Step 1: Making initial request to detect DataDome protection...');

        // Step 1: Make initial request to trigger DataDome
        await this._makeInitialRequest();

        // Step 2: Handle interstitial challenge if detected
        if (this.isInterstitial) {
            console.log('Step 2: Detected interstitial challenge, solving...');
            await this._solveInterstitial();

            // After interstitial, reload the page to check if we need slider or are done
            console.log('  Reloading page after interstitial...');
            await this._reloadPage();
        }

        // Step 3: Handle slider captcha if needed (either directly or after interstitial)
        if (!this.isInterstitial && this.deviceCheckLink) {
            console.log('Step 3: Detected slider captcha, solving...');
            await this._solveSliderCaptcha();

            // After slider, reload the page
            console.log('  Reloading page after slider...');
            await this._reloadPage();
        }

        // Step 4: Solve tags if enabled (signal collection for improved success rate)
        if (this.config.tagsEnabled) {
            console.log('Step 4: Solving tags (signal collection)...');
            await this._solveTags();
        }

        // Step 5: Verify access to protected page
        console.log('Step 5: Verifying access to protected page...');
        return await this._verifyAccess();
    }

    /**
     * Retrieves the client's public IP address.
     * @returns {Promise<string>}
     */
    async _getPublicIp() {
        const response = await this.session.get('https://api.ipify.org');
        return response.body.trim();
    }

    /**
     * Retrieves the current DataDome cookie value.
     * @returns {Promise<string>}
     */
    async _getDataDomeCookie() {
        try {
            const cookies = await this.session.getCookiesFromSession(
                this.session.getSession(),
                this.config.targetUrl
            );
            if (!cookies || !cookies.cookies || !Array.isArray(cookies.cookies)) {
                return '';
            }

            const cookie = cookies.cookies.find((c) => c.name === 'datadome');
            return cookie ? cookie.value : '';
        } catch {
            return '';
        }
    }

    /**
     * Updates the DataDome cookie from a Set-Cookie header value.
     * @param {string} cookieHeader
     * @returns {Promise<void>}
     */
    async _setDataDomeCookie(cookieHeader) {
        // Parse cookie from Set-Cookie header format
        // Example: "datadome=abc123; Domain=.example.com; ..."
        const parsedUrl = new URL(this.config.cookieDomain);
        const domain = parsedUrl.hostname;

        // Extract just the cookie value
        if (cookieHeader.includes('datadome=')) {
            // Extract value before first semicolon
            const parts = cookieHeader.split(';')[0];
            if (parts.includes('=')) {
                const value = parts.split('=').slice(1).join('=');
                await this.session.addCookiesToSession(this.session.getSession(), this.config.targetUrl, [
                    {
                        domain: domain,
                        path: '/',
                        name: 'datadome',
                        value: value,
                    },
                ]);
            }
        }
    }

    /**
     * Makes the first request to the target page to trigger DataDome.
     * @returns {Promise<void>}
     */
    async _makeInitialRequest() {
        const headers = {
            connection: 'keep-alive',
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'upgrade-insecure-requests': '1',
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'sec-fetch-site': 'none',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
        };

        const headerOrder = [
            'host',
            'connection',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'sec-ch-ua-platform',
            'upgrade-insecure-requests',
            'user-agent',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-user',
            'sec-fetch-dest',
            'accept-encoding',
            'accept-language',
        ];

        const response = await this.session.get(this.config.targetUrl, {
            headers,
            headerOrder,
        });

        const body = response.body;

        // Get the DataDome cookie value
        const ddCookie = await this._getDataDomeCookie();
        if (!ddCookie) {
            throw new Error('DataDome cookie not found - site may not be protected or IP may be blocked');
        }

        console.log(`  DataDome cookie obtained: ${ddCookie.substring(0, 20)}...`);

        // Detect challenge type and parse device check link
        if (body.includes('https://ct.captcha-delivery.com/i.js')) {
            // Interstitial challenge detected
            this.isInterstitial = true;
            this.deviceCheckLink = parseInterstitialDeviceCheckUrl(body, ddCookie, this.config.targetUrl);
            console.log('  Challenge type: Interstitial');
        } else {
            // Slider captcha challenge
            this.isInterstitial = false;
            this.deviceCheckLink = parseSliderDeviceCheckUrl(body, ddCookie, this.config.targetUrl);
            console.log('  Challenge type: Slider Captcha');
        }
    }

    /**
     * Reloads the target page after solving a challenge.
     * @returns {Promise<void>}
     */
    async _reloadPage() {
        const headers = {
            connection: 'keep-alive',
            'cache-control': 'max-age=0',
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'upgrade-insecure-requests': '1',
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document',
            referer: this.config.targetUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
        };

        const headerOrder = [
            'host',
            'connection',
            'cache-control',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'sec-ch-ua-platform',
            'upgrade-insecure-requests',
            'user-agent',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-user',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
        ];

        const response = await this.session.get(this.config.targetUrl, {
            headers,
            headerOrder,
        });

        const body = response.body;

        // Check if we got another challenge (slider after interstitial)
        const ddCookie = await this._getDataDomeCookie();

        if (body.includes('captcha-delivery.com')) {
            // Another challenge detected - parse the device check link
            try {
                this.deviceCheckLink = parseSliderDeviceCheckUrl(body, ddCookie, this.config.targetUrl);
                this.isInterstitial = false;
                console.log('  Additional slider challenge detected after reload');
            } catch {
                // Try interstitial
                try {
                    this.deviceCheckLink = parseInterstitialDeviceCheckUrl(
                        body,
                        ddCookie,
                        this.config.targetUrl
                    );
                    this.isInterstitial = true;
                    console.log('  Additional interstitial challenge detected after reload');
                } catch {
                    // No challenge found, we're good
                    this.deviceCheckLink = '';
                }
            }
        } else {
            // No challenge, clear the device check link
            this.deviceCheckLink = '';
        }
    }

    /**
     * Handles the interstitial challenge flow.
     * @returns {Promise<void>}
     */
    async _solveInterstitial() {
        // Step 2a: Fetch the interstitial page
        console.log('  Fetching interstitial page...');
        await this._fetchInterstitialPage();

        // Step 2b: Generate interstitial payload using Hyper API
        console.log('  Generating interstitial payload via Hyper API...');
        const result = await generateInterstitialPayload(
            this.hyperApi,
            new InterstitialInput(
                USER_AGENT,
                this.deviceCheckLink,
                this.html,
                this.ip,
                this.config.acceptLanguage
            )
        );
        const payload = result.payload;

        // Step 2c: Submit the interstitial payload
        console.log('  Submitting interstitial solution...');
        await this._submitInterstitial(payload);
    }

    /**
     * Retrieves the interstitial challenge HTML.
     * @returns {Promise<void>}
     */
    async _fetchInterstitialPage() {
        const headers = {
            connection: 'keep-alive',
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'upgrade-insecure-requests': '1',
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-dest': 'iframe',
            'sec-fetch-storage-access': 'none',
            referer: this.config.referer,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
        };

        const headerOrder = [
            'host',
            'connection',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'sec-ch-ua-platform',
            'upgrade-insecure-requests',
            'user-agent',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'sec-fetch-storage-access',
            'referer',
            'accept-encoding',
            'accept-language',
        ];

        const response = await this.session.get(this.deviceCheckLink, {
            headers,
            headerOrder,
        });

        this.html = response.body;
    }

    /**
     * Posts the generated payload to solve the interstitial.
     * @param {string} payload
     * @returns {Promise<void>}
     */
    async _submitInterstitial(payload) {
        const headers = {
            connection: 'keep-alive',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            origin: 'https://geo.captcha-delivery.com',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'sec-fetch-storage-access': 'none',
            referer: this.deviceCheckLink,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
        };

        const headerOrder = [
            'host',
            'connection',
            'content-length',
            'sec-ch-ua-platform',
            'user-agent',
            'sec-ch-ua',
            'content-type',
            'sec-ch-ua-mobile',
            'accept',
            'origin',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'sec-fetch-storage-access',
            'referer',
            'accept-encoding',
            'accept-language',
        ];

        const response = await this.session.post(
            'https://geo.captcha-delivery.com/interstitial/',
            payload,
            {
                headers,
                headerOrder,
            }
        );

        // Parse the response
        const result = JSON.parse(response.body);

        // Store the new cookie
        if (result.cookie) {
            await this._setDataDomeCookie(result.cookie);
        }

        console.log(`  Interstitial result: view=${result.view || 'unknown'}`);

        // Mark that we're no longer in interstitial mode
        this.isInterstitial = false;
        this.deviceCheckLink = '';
    }

    /**
     * Handles the slider captcha challenge flow.
     * @returns {Promise<void>}
     */
    async _solveSliderCaptcha() {
        // Step 3a: Fetch the captcha page
        console.log('  Fetching captcha page...');
        await this._fetchCaptchaPage();

        // Step 3b: Download puzzle images
        console.log('  Downloading puzzle images...');
        const puzzle = await this._downloadPuzzleImage();
        const piece = await this._downloadPieceImage();

        // Step 3c: Generate slider solution using Hyper API
        console.log('  Generating slider solution via Hyper API...');
        const result = await generateSliderPayload(
            this.hyperApi,
            new SliderInput(
                USER_AGENT,
                this.deviceCheckLink,
                this.html,
                puzzle,
                piece,
                this.ip,
                this.config.acceptLanguage,
                '' // parentUrl
            )
        );
        const checkUrl = result.payload;

        // Step 3d: Submit the slider solution
        console.log('  Submitting slider solution...');
        await this._submitSliderSolution(checkUrl);
    }

    /**
     * Retrieves the slider captcha HTML.
     * @returns {Promise<void>}
     */
    async _fetchCaptchaPage() {
        const headers = {
            connection: 'keep-alive',
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'upgrade-insecure-requests': '1',
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-dest': 'iframe',
            'sec-fetch-storage-access': 'none',
            referer: this.config.referer,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
        };

        const headerOrder = [
            'host',
            'connection',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'sec-ch-ua-platform',
            'upgrade-insecure-requests',
            'user-agent',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'sec-fetch-storage-access',
            'referer',
            'accept-encoding',
            'accept-language',
        ];

        const response = await this.session.get(this.deviceCheckLink, {
            headers,
            headerOrder,
        });

        this.html = response.body;

        // Extract the captcha challenge path from the HTML
        const match = this.html.match(/captchaChallengePath:\s*'(.*?)'/);
        if (!match) {
            throw new Error('Captcha challenge path not found in HTML');
        }

        this.captchaPath = match[1];
        console.log(`  Captcha path: ${this.captchaPath}`);
    }

    /**
     * Downloads the main puzzle background image and returns as string.
     * @returns {Promise<string>}
     */
    async _downloadPuzzleImage() {
        const headers = {
            origin: 'https://geo.captcha-delivery.com',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'image',
            referer: 'https://geo.captcha-delivery.com/',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'i',
        };

        const headerOrder = [
            'origin',
            'sec-ch-ua-platform',
            'user-agent',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'priority',
        ];

        const response = await this.session.get(this.captchaPath, {
            headers,
            headerOrder,
        });

        // Return raw binary data as string (latin-1 equivalent)
        return response.body;
    }

    /**
     * Downloads the slider piece image and returns as string.
     * @returns {Promise<string>}
     */
    async _downloadPieceImage() {
        // The piece image URL is derived from the puzzle URL by replacing .jpg with .frag.png
        const pieceUrl = this.captchaPath.replace('.jpg', '.frag.png');

        const headers = {
            origin: 'https://geo.captcha-delivery.com',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'image',
            referer: 'https://geo.captcha-delivery.com/',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'i',
        };

        const headerOrder = [
            'origin',
            'sec-ch-ua-platform',
            'user-agent',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'priority',
        ];

        const response = await this.session.get(pieceUrl, {
            headers,
            headerOrder,
        });

        // Return raw binary data as string (latin-1 equivalent)
        return response.body;
    }

    /**
     * Submits the generated slider solution.
     * @param {string} checkUrl
     * @returns {Promise<void>}
     */
    async _submitSliderSolution(checkUrl) {
        const headers = {
            connection: 'keep-alive',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'sec-fetch-storage-access': 'none',
            referer: this.deviceCheckLink,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
        };

        const headerOrder = [
            'host',
            'connection',
            'sec-ch-ua-platform',
            'user-agent',
            'sec-ch-ua',
            'content-type',
            'sec-ch-ua-mobile',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'sec-fetch-storage-access',
            'referer',
            'accept-encoding',
            'accept-language',
        ];

        const response = await this.session.get(checkUrl, {
            headers,
            headerOrder,
        });

        // Check for block (HTTP 403 means failed verification)
        if (response.status === 403) {
            throw new Error('Slider solution was rejected - captcha verification failed');
        }

        // Parse the response to get the new cookie
        const result = JSON.parse(response.body);

        // Store the new cookie
        if (result.cookie) {
            await this._setDataDomeCookie(result.cookie);
            console.log('  Slider captcha solved successfully!');
        }

        // Clear device check link since we've solved the captcha
        this.deviceCheckLink = '';
    }

    /**
     * Handles the DataDome tags/signal collection flow.
     * @returns {Promise<void>}
     */
    async _solveTags() {
        // Get current DataDome cookie
        let cid = await this._getDataDomeCookie();
        if (!cid) {
            throw new Error('DataDome cookie not found for tags');
        }

        // ==========================================================================
        // First tags request: "ch" (challenge) type
        // ==========================================================================
        console.log('  Sending first tags request (type: ch)...');
        const chPayload = await generateTagsPayload(
            this.hyperApi,
            new TagsInput(
                USER_AGENT,
                this.config.tagsDdk,
                this.config.referer,
                'ch',
                this.ip,
                this.config.acceptLanguage,
                this.config.tagsVersion,
                cid,
            )
        );

        await this._postTags(chPayload);

        // ==========================================================================
        // Sleep between requests to simulate real user behavior
        // ==========================================================================
        console.log('  Waiting 5 seconds before second tags request...');
        await new Promise((resolve) => setTimeout(resolve, 5000));

        // ==========================================================================
        // Second tags request: "le" (loaded events) type
        // Refresh the cookie as it may have been updated
        // ==========================================================================
        cid = await this._getDataDomeCookie();

        console.log('  Sending second tags request (type: le)...');
        const lePayload = await generateTagsPayload(
            this.hyperApi,
            new TagsInput(
                USER_AGENT,
                this.config.tagsDdk,
                this.config.referer,
                'le',
                this.ip,
                this.config.acceptLanguage,
                this.config.tagsVersion,
                cid,
            )
        );

        await this._postTags(lePayload);

        console.log('  Tags solved successfully!');
    }

    /**
     * Sends a tags payload to the DataDome tags endpoint.
     * @param {string} payload
     * @returns {Promise<void>}
     */
    async _postTags(payload) {
        // Extract origin from referer for the Origin header
        const parsedReferer = new URL(this.config.referer);
        const origin = `${parsedReferer.protocol}//${parsedReferer.host}`;

        const headers = {
            'sec-ch-ua': SEC_CH_UA,
            'content-type': 'application/x-www-form-urlencoded',
            'sec-ch-ua-mobile': '?0',
            'user-agent': USER_AGENT,
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            accept: '*/*',
            origin: origin,
            'sec-fetch-site': 'cross-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            referer: this.config.referer,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1, i',
        };

        const headerOrder = [
            'content-length',
            'sec-ch-ua',
            'content-type',
            'sec-ch-ua-mobile',
            'user-agent',
            'sec-ch-ua-platform',
            'accept',
            'origin',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'priority',
        ];

        const response = await this.session.post(this.config.tagsEndpoint, payload, {
            headers,
            headerOrder,
        });

        // Parse the response to get the updated cookie
        const result = JSON.parse(response.body);

        // Update cookie if provided
        if (result.cookie) {
            await this._setDataDomeCookie(result.cookie);
        }
    }

    /**
     * Makes a final request to verify we can access the protected page.
     * @returns {Promise<boolean>}
     */
    async _verifyAccess() {
        const headers = {
            'cache-control': 'max-age=0',
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'upgrade-insecure-requests': '1',
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-user': '?1',
            'sec-fetch-dest': 'document',
            referer: this.config.targetUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=0, i',
        };

        const headerOrder = [
            'host',
            'cache-control',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'sec-ch-ua-platform',
            'upgrade-insecure-requests',
            'user-agent',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-user',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'cookie',
            'priority',
        ];

        const response = await this.session.get(this.config.targetUrl, {
            headers,
            headerOrder,
        });

        const success = response.status !== 403;
        if (success) {
            console.log(`Success! Access granted (HTTP ${response.status})`);
        } else {
            console.log(`Failed! Access denied (HTTP ${response.status})`);
        }

        return success;
    }

    /**
     * Releases resources associated with the solver.
     * @returns {Promise<void>}
     */
    async close() {
        try {
            await this.session.destroySession();
            await this.moduleClient.terminate();
        } catch {
            // Ignore cleanup errors
        }
    }
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

async function main() {
    // Load configuration
    const config = defaultConfig();

    // Configure for your target site
    config.targetUrl = 'https://tickets.example.com/';
    config.referer = 'https://tickets.example.com/';
    config.cookieDomain = 'https://example.com/';

    // Enable tags solving for improved success rate
    config.tagsEnabled = true;
    config.tagsDdk = 'EXAMPLEDDK'; // Site-specific DataDome key
    config.tagsVersion = '5.1.13'; // DataDome tags version
    config.tagsEndpoint = 'https://datadome.seatgeek.com/js/';

    // Validate API key
    if (!config.apiKey) {
        console.error(
            'HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co'
        );
        process.exit(1);
    }

    // Create and run solver
    const solver = new DataDomeSolver(config);
    try {
        const success = await solver.solve();

        if (success) {
            console.log('\n✅ DataDome bypass successful!');
            console.log('You can now make authenticated requests using the same session.');
        } else {
            console.log('\n❌ DataDome bypass failed.');
            console.log('The IP may be blocked or additional challenges are required.');
            process.exit(1);
        }
    } catch (error) {
        console.error('Solver error:', error);
        process.exit(1);
    } finally {
        await solver.close();
    }
}

// Run if executed directly
main().catch(console.error);

export { DataDomeSolver, defaultConfig };