/**
 * Akamai Bot Manager Bypass Example using tlsclientwrapper and Hyper Solutions SDK
 *
 * This example demonstrates:
 *   - Setting up a TLS client session with Chrome browser impersonation
 *   - Detecting and solving SBSD (State-Based Scraping Detection) challenges
 *   - Handling SBSD with and without the "t" parameter
 *   - Generating and submitting sensor data via the Hyper API
 *   - Cookie validation and the complete bypass flow
 *
 * For more information, visit: https://docs.hypersolutions.co
 * Join our Discord community: https://discord.gg/akamai
 */

import { ModuleClient, SessionClient } from 'tlsclientwrapper';
import {
    Session as HyperSession,
    SensorInput,
    SbsdInput,
    generateSensorData,
    generateSbsdPayload,
    parseAkamaiPath,
    isAkamaiCookieValid,
} from 'hyper-sdk-js';

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Configuration for the Akamai bypass example.
 * @typedef {Object} Config
 * @property {string} apiKey - Your Hyper Solutions API key
 * @property {string} targetUrl - The protected page you want to access
 * @property {string} referer - The HTTP referer header value
 * @property {string} acceptLanguage - The browser's accept-language header
 * @property {string|null} proxyUrl - Optional HTTP/HTTPS/SOCKS5 proxy
 * @property {number} timeout - HTTP request timeout in seconds
 * @property {string} version - Akamai version (usually "2" or "3")
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
        acceptLanguage: 'en-US,en;q=0.9',
        proxyUrl: process.env.HTTP_PROXY || null,
        timeout: 30,
        version: '3',
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

// SBSD regex pattern
const SBSD_REGEX = /(?:([a-z\d/\-_\.]+)\?v=(.*?)(?:&.*?t=(.*?))?["'])/i;

// =============================================================================
// SBSD INFO
// =============================================================================

/**
 * Holds extracted SBSD information from the page.
 */
class SbsdInfo {
    /**
     * @param {string} path - Script path (e.g., /abc/def)
     * @param {string} uuid - UUID/version parameter
     * @param {string} t - Optional "t" parameter (indicates hardblock if present)
     */
    constructor(path, uuid, t = '') {
        this.path = path;
        this.uuid = uuid;
        this.t = t;
    }

    /**
     * Returns true if SBSD is in hardblock mode (t parameter present).
     * @returns {boolean}
     */
    isHardblock() {
        return this.t !== '';
    }

    /**
     * Returns the full URL to fetch the SBSD script.
     * @param {string} baseUrl
     * @returns {string}
     */
    scriptUrl(baseUrl) {
        const url = new URL(baseUrl);
        let scriptUrl = `${url.protocol}//${url.host}${this.path}?v=${this.uuid}`;
        if (this.t) {
            scriptUrl += `&t=${this.t}`;
        }
        return scriptUrl;
    }

    /**
     * Returns the URL for posting SBSD payloads.
     * @param {string} baseUrl
     * @returns {string}
     */
    postUrl(baseUrl) {
        const url = new URL(baseUrl);
        let postUrl = `${url.protocol}//${url.host}${this.path}`;
        if (this.t) {
            postUrl += `?t=${this.t}`;
        }
        return postUrl;
    }
}

/**
 * Attempts to extract SBSD information from page HTML.
 * @param {string} html
 * @returns {SbsdInfo|null}
 */
function parseSbsdInfo(html) {
    const matches = html.match(SBSD_REGEX);
    if (!matches || matches.length < 3) {
        return null;
    }

    return new SbsdInfo(matches[1], matches[2], matches[3] || '');
}

// =============================================================================
// AKAMAI SOLVER
// =============================================================================

/**
 * Handles the complete Akamai bypass flow.
 */
class AkamaiSolver {
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
        this.pageHtml = '';
        this.sbsdInfo = null;
        this.sbsdScript = '';
        this.sensorScript = '';
        this.sensorEndpoint = '';
        this.sensorContext = '';
    }

    /**
     * Attempts to bypass Akamai protection and access the target page.
     * @returns {Promise<boolean>} True if successful, false if blocked.
     */
    async solve() {
        // Get public IP
        this.ip = await this._getPublicIp();
        console.log(`Public IP: ${this.ip}`);

        console.log('Step 1: Making initial request to detect Akamai protection...');

        // Step 1: Fetch the page and detect protection type
        await this._fetchPage();

        // Step 2: Handle SBSD if detected
        if (this.sbsdInfo) {
            console.log(`Step 2: SBSD detected (hardblock=${this.sbsdInfo.isHardblock()}), solving...`);
            await this._solveSbsd();
        } else {
            console.log('Step 2: No SBSD detected, skipping...');
        }

        // Step 3: Handle sensor flow
        console.log('Step 3: Starting sensor flow...');
        if (!this._parseSensorEndpoint()) {
            console.log('  Sensor endpoint not found, skipping sensor posts');
            return true;
        }

        await this._fetchSensorScript();

        // Step 4: Submit sensors (up to 3 times)
        console.log('Step 4: Submitting sensors...');
        for (let i = 0; i < 3; i++) {
            console.log(`  Sensor attempt ${i + 1}/3...`);
            await this._postSensor(i);

            // Check if cookie is valid
            const abck = await this._getCookie('_abck');
            if (isAkamaiCookieValid(abck, i)) {
                console.log(`  Cookie valid after ${i + 1} sensor(s)!`);
                return true;
            }
        }

        // Check final cookie state
        const abck = await this._getCookie('_abck');
        if (!abck.includes('~')) {
            console.log(
                "Warning: Cookie doesn't contain stopping signal (~). Site may not use stopping signal, or cookie is invalid."
            );
        }

        return true;
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
     * Makes a GET request to the target page and extracts protection info.
     * @returns {Promise<void>}
     */
    async _fetchPage() {
        const headers = {
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
            priority: 'u=0, i',
        };

        const headerOrder = [
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
            'priority',
        ];

        const response = await this.session.get(this.config.targetUrl, {
            headers,
            headerOrder,
        });

        this.pageHtml = response.body;

        // Check for SBSD
        this.sbsdInfo = parseSbsdInfo(this.pageHtml);
        if (this.sbsdInfo) {
            console.log(
                `  SBSD detected: path=${this.sbsdInfo.path}, uuid=${this.sbsdInfo.uuid}, t=${this.sbsdInfo.t}`
            );
        }
    }

    /**
     * Handles the SBSD challenge flow.
     * @returns {Promise<void>}
     */
    async _solveSbsd() {
        // Fetch SBSD script
        console.log('  Fetching SBSD script...');
        await this._fetchSbsdScript();

        if (this.sbsdInfo.isHardblock()) {
            // Hardblock mode: post once, then reload page
            console.log('  Hardblock mode: posting single SBSD payload...');
            await this._postSbsd(0);

            // Reload the page
            console.log('  Reloading page after SBSD...');
            await this._fetchPage();
        } else {
            // Non-hardblock mode: post twice with index 0 and 1
            console.log('  Non-hardblock mode: posting two SBSD payloads...');
            await this._postSbsd(0);
            await this._postSbsd(1);
        }
    }

    /**
     * Retrieves the SBSD script content.
     * @returns {Promise<void>}
     */
    async _fetchSbsdScript() {
        const scriptUrl = this.sbsdInfo.scriptUrl(this.config.targetUrl);

        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-dest': 'script',
            referer: this.config.targetUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1',
        };

        const headerOrder = [
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
            'cookie',
            'priority',
        ];

        const response = await this.session.get(scriptUrl, {
            headers,
            headerOrder,
        });

        this.sbsdScript = response.body;
        console.log(`  SBSD script fetched: ${this.sbsdScript.length} bytes`);
    }

    /**
     * Submits an SBSD payload.
     * @param {number} index
     * @returns {Promise<void>}
     */
    async _postSbsd(index) {
        // Get the O cookie (bm_so or sbsd_o)
        let oCookie = await this._getCookie('bm_so');
        if (!oCookie) {
            oCookie = await this._getCookie('sbsd_o');
        }

        const sbsdInput = new SbsdInput(
            index,
            this.sbsdInfo.uuid,
            oCookie || '',
            this.config.targetUrl,
            USER_AGENT,
            this.sbsdScript,
            this.ip,
            this.config.acceptLanguage,
        );

        const payload = await generateSbsdPayload(this.hyperApi, sbsdInput);

        const postUrl = this.sbsdInfo.postUrl(this.config.targetUrl);

        // Wrap payload in JSON body
        const bodyJson = JSON.stringify({ body: payload });

        const parsedUrl = new URL(this.config.targetUrl);
        const origin = `${parsedUrl.protocol}//${parsedUrl.host}`;

        const headers = {
            'sec-ch-ua': SEC_CH_UA,
            'content-type': 'application/json',
            'sec-ch-ua-mobile': '?0',
            'user-agent': USER_AGENT,
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            accept: '*/*',
            origin,
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            referer: this.config.targetUrl,
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
            'cookie',
            'priority',
        ];

        await this.session.post(postUrl, bodyJson, {
            headers,
            headerOrder,
        });

        console.log(`  SBSD payload ${index} submitted`);
    }

    /**
     * Extracts the sensor script endpoint from page HTML.
     * @returns {boolean}
     */
    _parseSensorEndpoint() {
        try {
            const scriptPath = parseAkamaiPath(this.pageHtml);
            if (!scriptPath) {
                return false;
            }

            const parsedUrl = new URL(this.config.targetUrl);
            this.sensorEndpoint = `${parsedUrl.protocol}//${parsedUrl.host}${scriptPath}`;
            console.log(`  Sensor endpoint: ${this.sensorEndpoint}`);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Retrieves the Akamai sensor script content.
     * @returns {Promise<void>}
     */
    async _fetchSensorScript() {
        const headers = {
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'user-agent': USER_AGENT,
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-dest': 'script',
            referer: this.config.targetUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1',
        };

        const headerOrder = [
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'user-agent',
            'sec-ch-ua-platform',
            'accept',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'cookie',
            'priority',
        ];

        const response = await this.session.get(this.sensorEndpoint, {
            headers,
            headerOrder,
        });

        this.sensorScript = response.body;
        console.log(`  Sensor script fetched: ${this.sensorScript.length} bytes`);
    }

    /**
     * Submits sensor data to the Akamai endpoint.
     * @param {number} iteration
     * @returns {Promise<void>}
     */
    async _postSensor(iteration) {
        const sensorInput = new SensorInput(
            await this._getCookie('_abck') || '',
            await this._getCookie('bm_sz') || '',
            this.config.version,
            this.config.targetUrl,
            USER_AGENT,
            this.ip,
            this.config.acceptLanguage,
            this.sensorContext,
            // Only include script on first sensor
            iteration === 0 ? this.sensorScript : '',
            this.sensorEndpoint,
        );

        const result = await generateSensorData(this.hyperApi, sensorInput);

        // Store context for subsequent requests
        this.sensorContext = result.context || '';

        // Wrap sensor data in JSON
        const bodyJson = JSON.stringify({ sensor_data: result.payload });

        const parsedUrl = new URL(this.config.targetUrl);
        const origin = `${parsedUrl.protocol}//${parsedUrl.host}`;

        const headers = {
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'sec-ch-ua-mobile': '?0',
            'user-agent': USER_AGENT,
            'content-type': 'text/plain;charset=UTF-8',
            accept: '*/*',
            origin,
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            referer: this.config.targetUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1, i',
        };

        const headerOrder = [
            'content-length',
            'sec-ch-ua',
            'sec-ch-ua-platform',
            'sec-ch-ua-mobile',
            'user-agent',
            'content-type',
            'accept',
            'origin',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'cookie',
            'priority',
        ];

        await this.session.post(this.sensorEndpoint, bodyJson, {
            headers,
            headerOrder,
        });
    }

    /**
     * Retrieves a cookie value by name from the session's cookie jar.
     * @param {string} name
     * @returns {string}
     */
    async _getCookie(name) {
        try {
            const cookies = await this.session.getCookiesFromSession(this.session.getSession(), this.config.targetUrl);
            if (!cookies || !cookies.cookies || !Array.isArray(cookies.cookies)) {
                return '';
            }

            const cookie = cookies.cookies.find((c) => c.name === name);
            return cookie ? cookie.value : '';
        } catch {
            return '';
        }
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
    config.targetUrl = 'https://www.example.com/us/en';
    config.referer = 'https://www.example.com/us/en';
    config.version = '3'; // Akamai version

    // Validate API key
    if (!config.apiKey) {
        console.error(
            'HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co'
        );
        process.exit(1);
    }

    // Create and run solver
    const solver = new AkamaiSolver(config);
    try {
        const success = await solver.solve();

        if (success) {
            console.log('\n✅ Akamai bypass successful!');
            console.log('You can now make authenticated requests using the same session.');
        } else {
            console.log('\n❌ Akamai bypass failed.');
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

export { AkamaiSolver, SbsdInfo, parseSbsdInfo, defaultConfig };