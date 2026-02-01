/**
 * Kasada Bypass Example using tlsclientwrapper and Hyper Solutions SDK
 *
 * This example demonstrates:
 *   - Setting up a TLS client session with Chrome browser impersonation
 *   - Detecting Kasada protection (429 on page vs /fp endpoint)
 *   - Fetching and solving ips.js challenges
 *   - Generating payload data (CT) and POW tokens (CD)
 *   - Handling BotID verification when required
 *   - The complete flow from initial request to successful bypass
 *
 * For more information, visit: https://docs.hypersolutions.co
 * Join our Discord community: https://discord.gg/akamai
 */

import { ModuleClient, SessionClient } from 'tlsclientwrapper';
import {
    Session as HyperSession,
    KasadaPayloadInput,
    KasadaPowInput,
    BotIDHeaderInput,
    generateKasadaPayload,
    generateKasadaPow,
    generateBotIDHeader,
    parseKasadaPath,
} from 'hyper-sdk-js';

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Configuration for the Kasada bypass example.
 * @typedef {Object} Config
 * @property {string} apiKey - Your Hyper Solutions API key
 * @property {string} pageUrl - The protected page you want to access
 * @property {string} acceptLanguage - The browser's accept-language header
 * @property {string|null} proxyUrl - Optional HTTP/HTTPS/SOCKS5 proxy
 * @property {number} timeout - HTTP request timeout in seconds
 * @property {boolean} botIdEnabled - Enable BotID/Vercel protection solving
 */

/**
 * Returns a sensible default configuration.
 * You MUST replace the apiKey and pageUrl with your own values.
 * @returns {Config}
 */
function defaultConfig() {
    return {
        apiKey: process.env.HYPER_API_KEY || '',
        pageUrl: 'https://example.com/protected-page',
        acceptLanguage: 'en-US,en;q=0.9',
        proxyUrl: process.env.HTTP_PROXY || null,
        timeout: 30,
        botIdEnabled: false,
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

// Kasada SDK version
const KASADA_VERSION = 'j-1.1.29140';

// Fixed Kasada paths
const KASADA_BASE_PATH = '/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3';

// =============================================================================
// KASADA SOLVER
// =============================================================================

/**
 * Handles the complete Kasada bypass flow.
 */
class KasadaSolver {
    /**
     * @param {Config} config
     */
    constructor(config) {
        if (!config.apiKey) {
            throw new Error('API key is required - get yours at https://hypersolutions.co');
        }
        if (!config.pageUrl) {
            throw new Error('Page URL is required');
        }

        this.config = config;

        // Parse domain from page URL
        const parsedUrl = new URL(config.pageUrl);
        this.domain = parsedUrl.host;
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
            isByteRequest: true,
        };

        if (config.proxyUrl) {
            sessionOptions.proxyUrl = config.proxyUrl;
        }

        this.session = new SessionClient(this.moduleClient, sessionOptions);

        // Create Hyper Solutions API session
        this.hyperApi = new HyperSession(config.apiKey);

        // Internal state
        this.ip = '';
        this.ipsScript = '';
        this.ipsLink = '';

        // Headers from /tl response
        this.tlCt = '';
        this.tlSt = 0;

        // Headers from /mfc response
        this.mfcFc = '';
        this.mfcH = '';
    }

    /**
     * Attempts to bypass Kasada protection and access the target page.
     * @returns {Promise<boolean>} True if successful, false if blocked.
     */
    async solve() {
        // Get public IP
        this.ip = await this._getPublicIp();
        console.log(`Public IP: ${this.ip}`);

        console.log('Step 1: Making initial request to detect Kasada protection...');

        // Step 1: Fetch the page and check for 429
        const { statusCode, body: pageBody } = await this._fetchPage();

        if (statusCode === 429) {
            // Flow 1: 429 on page URL - solve and reload
            console.log('Step 2: Detected 429 on page, solving Kasada challenge...');
            await this._solveFromBlockPage(pageBody);

            // Reload page
            console.log('Step 3: Reloading page after solving...');
            const { statusCode: reloadStatus } = await this._fetchPage();

            if (reloadStatus !== 200) {
                console.log(`Failed! Page still returning ${reloadStatus} after solve`);
                return false;
            }

            console.log('  Page loaded successfully!');
        } else {
            // Flow 2: No 429 on page - solve via /fp endpoint
            console.log('Step 2: No 429 on page, solving via /fp endpoint...');
            await this._solveFromFpEndpoint();
        }

        // Step 4: Handle BotID if enabled
        if (this.config.botIdEnabled) {
            console.log('Step 4: Solving BotID challenge...');
            await this._solveBotId();
        } else {
            console.log('Step 4: BotID disabled, skipping...');
        }

        // Step 5: Generate POW (x-kpsdk-cd) for demonstration
        console.log('Step 5: Generating POW (x-kpsdk-cd) for API requests...');
        await this._generatePow();

        console.log('\n✅ Kasada bypass successful!');
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
     * Makes a GET request to the page URL.
     * @returns {Promise<{statusCode: number, body: string}>}
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
            'cookie',
            'priority',
        ];

        const response = await this.session.get(this.config.pageUrl, {
            headers,
            headerOrder,
        });

        console.log(`  Page response: ${response.status}`);

        return { statusCode: response.status, body: response.body };
    }

    /**
     * Handles the flow when page returns 429.
     * @param {string} blockPageBody
     * @returns {Promise<void>}
     */
    async _solveFromBlockPage(blockPageBody) {
        // Extract ips.js URL from block page
        const ipsPath = parseKasadaPath(blockPageBody);
        this.ipsLink = this.baseUrl + ipsPath;
        console.log(`  IPS script URL: ${this.ipsLink}`);

        // Fetch ips.js script
        await this._fetchIpsScript();

        // Generate and submit payload
        await this._solveChallenge();
    }

    /**
     * Handles the flow when page doesn't return 429.
     * @returns {Promise<void>}
     */
    async _solveFromFpEndpoint() {
        // Request /fp endpoint to trigger 429
        const fpUrl = `${this.baseUrl}${KASADA_BASE_PATH}/fp?x-kpsdk-v=${KASADA_VERSION}`;

        const headers = {
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'upgrade-insecure-requests': '1',
            'user-agent': USER_AGENT,
            accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-dest': 'iframe',
            referer: this.config.pageUrl,
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
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'cookie',
            'priority',
        ];

        const response = await this.session.get(fpUrl, {
            headers,
            headerOrder,
        });

        if (response.status !== 429) {
            throw new Error(`/fp returned unexpected status code: ${response.status}`);
        }

        console.log('  /fp returned 429, extracting script...');

        // Extract ips.js URL
        const ipsPath = parseKasadaPath(response.body);
        this.ipsLink = this.baseUrl + ipsPath;
        console.log(`  IPS script URL: ${this.ipsLink}`);

        // Fetch ips.js script
        await this._fetchIpsScript();

        // Generate and submit payload
        await this._solveChallenge();
    }

    /**
     * Retrieves the ips.js script content.
     * @returns {Promise<void>}
     */
    async _fetchIpsScript() {
        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-dest': 'script',
            referer: this.config.pageUrl,
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

        const response = await this.session.get(this.ipsLink, {
            headers,
            headerOrder,
        });

        if (response.status !== 200) {
            throw new Error(`ips.js request returned ${response.status}`);
        }

        this.ipsScript = response.body;
        console.log(`  IPS script fetched: ${this.ipsScript.length} bytes`);
    }

    /**
     * Generates payload and submits to /tl endpoint.
     * @returns {Promise<void>}
     */
    async _solveChallenge() {
        console.log('  Generating Kasada payload via Hyper API...');

        // Generate payload
        const result = await generateKasadaPayload(
            this.hyperApi,
            new KasadaPayloadInput(
                USER_AGENT,
                this.ipsLink,
                this.ipsScript,
                this.ip,
                this.config.acceptLanguage,
            )
        );

        // Decode base64 payload
        const payloadB64 = result.payload;
        const headersDict = result.headers;

        console.log('  Submitting payload to /tl...');

        // Submit to /tl
        const tlUrl = `${this.baseUrl}${KASADA_BASE_PATH}/tl`;

        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'user-agent': USER_AGENT,
            'content-type': 'application/octet-stream',
            accept: '*/*',
            origin: this.baseUrl,
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            referer: this.config.pageUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1, i',
        };

        // Build header order with Kasada headers at the front
        const headerOrder = ['content-length'];

        // Add Kasada headers from payload generation
        if (headersDict['x-kpsdk-ct']) {
            headers['x-kpsdk-ct'] = headersDict['x-kpsdk-ct'];
            headerOrder.push('x-kpsdk-ct');
        }
        if (headersDict['x-kpsdk-dt']) {
            headers['x-kpsdk-dt'] = headersDict['x-kpsdk-dt'];
            headerOrder.push('x-kpsdk-dt');
        }
        if (headersDict['x-kpsdk-v']) {
            headers['x-kpsdk-v'] = headersDict['x-kpsdk-v'];
        }
        if (headersDict['x-kpsdk-r']) {
            headers['x-kpsdk-r'] = headersDict['x-kpsdk-r'];
        }
        if (headersDict['x-kpsdk-dv']) {
            headers['x-kpsdk-dv'] = headersDict['x-kpsdk-dv'];
        }
        if (headersDict['x-kpsdk-h']) {
            headers['x-kpsdk-h'] = headersDict['x-kpsdk-h'];
        }
        if (headersDict['x-kpsdk-fc']) {
            headers['x-kpsdk-fc'] = headersDict['x-kpsdk-fc'];
        }
        if (headersDict['x-kpsdk-im']) {
            headers['x-kpsdk-im'] = headersDict['x-kpsdk-im'];
            headerOrder.push('x-kpsdk-im');
        }

        headerOrder.push(
            'sec-ch-ua-platform',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'x-kpsdk-v',
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
            'priority'
        );

        const response = await this.session.post(tlUrl, payloadB64, {
            headers,
            headerOrder,
        });

        if (response.status !== 200) {
            throw new Error(`/tl returned ${response.status}`);
        }

        // Check for reload:true
        const tlResponse = JSON.parse(response.body);

        if (!tlResponse.reload) {
            throw new Error('/tl did not return reload:true');
        }

        console.log('  /tl returned reload:true - challenge solved!');

        // Store headers for POW generation
        // Note: Response headers access may vary depending on tlsclientwrapper implementation
        this.tlCt = response.headers?.['x-kpsdk-ct'] || '';
        const stStr = response.headers?.['x-kpsdk-st'] || '';
        if (stStr) {
            this.tlSt = parseInt(stStr, 10);
        }

        // Log response headers
        console.log('\n  Response headers from /tl:');
        console.log(`    x-kpsdk-ct: ${this.tlCt}`);
        console.log(`    x-kpsdk-st: ${this.tlSt}`);
    }

    /**
     * Handles the BotID/Vercel verification.
     * @returns {Promise<void>}
     */
    async _solveBotId() {
        // Fetch BotID script
        const botIdUrl = `${this.baseUrl}${KASADA_BASE_PATH}/a-4-a/c.js?i=0&v=3&h=${this.domain}`;

        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-dest': 'script',
            referer: this.config.pageUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
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
        ];

        const response = await this.session.get(botIdUrl, {
            headers,
            headerOrder,
        });

        if (response.status !== 200) {
            throw new Error(`BotID script request returned ${response.status}`);
        }

        console.log(`  BotID script fetched: ${response.body.length} bytes`);

        // Generate BotID header
        const isHumanHeader = await generateBotIDHeader(
            this.hyperApi,
            new BotIDHeaderInput(
                response.body,
                USER_AGENT,
                this.ip,
                this.config.acceptLanguage
            )
        );

        console.log(`  x-is-human header generated: ${isHumanHeader.substring(0, 50)}...`);
    }

    /**
     * Generates the x-kpsdk-cd header for protected API requests.
     * @returns {Promise<void>}
     */
    async _generatePow() {
        // First, make /mfc request to get fc and h headers
        console.log('  Making /mfc request...');

        const mfcUrl = `${this.baseUrl}${KASADA_BASE_PATH}/mfc`;

        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'x-kpsdk-h': '01',
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'x-kpsdk-v': KASADA_VERSION,
            'user-agent': USER_AGENT,
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            referer: this.config.pageUrl,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1, i',
        };

        const headerOrder = [
            'sec-ch-ua-platform',
            'x-kpsdk-h',
            'sec-ch-ua',
            'sec-ch-ua-mobile',
            'x-kpsdk-v',
            'user-agent',
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

        const response = await this.session.get(mfcUrl, {
            headers,
            headerOrder,
        });

        // Note: Response headers access may vary depending on tlsclientwrapper implementation
        this.mfcFc = response.headers?.['x-kpsdk-fc'] || '';
        this.mfcH = response.headers?.['x-kpsdk-h'] || '';

        console.log(
            `  /mfc headers - x-kpsdk-fc: ${this.mfcFc.substring(0, 30)}..., x-kpsdk-h: ${this.mfcH}`
        );

        // Generate POW
        console.log('  Generating x-kpsdk-cd via Hyper API...');

        const cd = await generateKasadaPow(
            this.hyperApi,
            new KasadaPowInput(this.tlSt, this.tlCt, this.mfcFc, this.domain)
        );

        console.log('\n  ✅ POW generated successfully!');
        console.log('\n  Headers for protected API requests:');
        console.log(`    x-kpsdk-ct: ${this.tlCt}`);
        console.log(`    x-kpsdk-cd: ${cd}`);
        console.log(`    x-kpsdk-h:  ${this.mfcH}`);
        console.log(`    x-kpsdk-v:  ${KASADA_VERSION}`);
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
    config.pageUrl = 'https://www.example.com/';

    // Enable BotID if the site uses Vercel BotID protection
    config.botIdEnabled = false;

    // Validate API key
    if (!config.apiKey) {
        console.error(
            'HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co'
        );
        process.exit(1);
    }

    // Create and run solver
    const solver = new KasadaSolver(config);
    try {
        const success = await solver.solve();

        if (success) {
            console.log('\nYou can now make authenticated requests using the same session.');
            console.log(
                'Remember to include x-kpsdk-ct, x-kpsdk-cd, x-kpsdk-h, and x-kpsdk-v headers on protected API requests.'
            );
        } else {
            console.log('\n❌ Kasada bypass failed.');
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

export { KasadaSolver, defaultConfig };