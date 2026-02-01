/**
 * Incapsula Reese84 Bypass Example using tlsclientwrapper and Hyper Solutions SDK
 *
 * This example demonstrates:
 *   - Setting up a TLS client session with Chrome browser impersonation
 *   - Detecting Incapsula protection and extracting script paths
 *   - Fetching the Reese84 script content
 *   - Handling POW (Proof of Work) challenges when required
 *   - Generating and submitting Reese84 sensors via the Hyper API
 *   - Handling the complete flow from initial request to successful bypass
 *
 * For more information, visit: https://docs.hypersolutions.co
 * Join our Discord community: https://discord.gg/akamai
 */

import { ModuleClient, SessionClient } from 'tlsclientwrapper';
import {
    Session as HyperSession,
    Reese84Input,
    generateReese84Sensor,
} from 'hyper-sdk-js';

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Configuration for the Incapsula Reese84 bypass example.
 * @typedef {Object} Config
 * @property {string} apiKey - Your Hyper Solutions API key
 * @property {string} targetUrl - The protected page you want to access
 * @property {string} referer - The HTTP referer header value
 * @property {string} cookieDomain - The domain for storing the Reese84 cookie
 * @property {string} acceptLanguage - The browser's accept-language header
 * @property {string|null} proxyUrl - Optional HTTP/HTTPS/SOCKS5 proxy
 * @property {number} timeout - HTTP request timeout in seconds
 * @property {boolean} powEnabled - Enable POW challenge solving
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
        powEnabled: false,
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
// INCAPSULA REESE84 SOLVER
// =============================================================================

/**
 * Handles the complete Incapsula Reese84 bypass flow.
 */
class Reese84Solver {
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
        this.path = ''; // Script path for sensor POST endpoint (e.g., /abc123/def456)
        this.fullPath = ''; // Full script path with query params for fetching
        this.script = ''; // Full Reese84 script content
    }

    /**
     * Attempts to bypass Incapsula Reese84 protection and access the target page.
     * @returns {Promise<boolean>} True if successful, false if blocked.
     */
    async solve() {
        // Get public IP
        this.ip = await this._getPublicIp();
        console.log(`Public IP: ${this.ip}`);

        console.log('Step 1: Making initial request to detect Incapsula protection...');

        // Step 1: Make initial request to trigger Incapsula and extract script paths
        await this._makeInitialRequest();

        // Step 2: Fetch the Reese84 script content
        console.log('Step 2: Fetching Reese84 script...');
        await this._fetchScript();

        // Step 3: Get POW challenge if enabled
        let powValue = '';
        if (this.config.powEnabled) {
            console.log('Step 3: Fetching POW challenge...');
            powValue = await this._getPow();
            console.log(`  POW obtained: ${powValue.substring(0, 30)}...`);
        } else {
            console.log('Step 3: POW disabled, skipping...');
        }

        // Step 4: Generate sensor via Hyper API
        console.log('Step 4: Generating Reese84 sensor via Hyper API...');
        const sensor = await this._generateSensor(powValue);
        console.log(`  Sensor generated: ${sensor.substring(0, 50)}...`);

        // Step 5: Submit the sensor
        console.log('Step 5: Submitting sensor...');
        await this._submitSensor(sensor);

        // Step 6: Verify access to protected page
        console.log('Step 6: Verifying access to protected page...');
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
     * Makes the first request to the target page to trigger Incapsula.
     * @returns {Promise<void>}
     */
    async _makeInitialRequest() {
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

        const body = response.body;

        // Check for Incapsula challenge page
        if (!body.includes('Pardon Our Interruption')) {
            throw new Error(
                'Incapsula challenge not detected - site may not be protected or IP may be blocked'
            );
        }

        console.log('  Incapsula challenge detected!');

        // Extract script path for sensor POST endpoint
        // Pattern: src="/abc123/def456?..."
        const pathRegex = /src\s*=\s*"(\/[^/]+\/[^?]+)\?.*"/;
        const pathMatches = body.match(pathRegex);
        if (!pathMatches || pathMatches.length < 2) {
            throw new Error('Failed to extract script path from challenge page');
        }
        this.path = pathMatches[1];
        console.log(`  Script path: ${this.path}`);

        // Extract full script path with query params for fetching
        // Pattern: scriptElement.src = "/abc123/def456?d=example.com&..."
        const fullPathRegex = /scriptElement\.src\s*=\s*"(.*?)"/;
        const fullPathMatches = body.match(fullPathRegex);
        if (!fullPathMatches || fullPathMatches.length < 2) {
            throw new Error('Failed to extract full script path from challenge page');
        }
        this.fullPath = fullPathMatches[1];
        console.log(`  Full script path: ${this.fullPath}`);
    }

    /**
     * Retrieves the Reese84 script content.
     * @returns {Promise<void>}
     */
    async _fetchScript() {
        const parsedUrl = new URL(this.config.targetUrl);
        const scriptUrl = `${parsedUrl.protocol}//${parsedUrl.host}${this.fullPath}`;

        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-dest': 'script',
            referer: this.config.referer,
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
        ];

        const response = await this.session.get(scriptUrl, {
            headers,
            headerOrder,
        });

        this.script = response.body;
        console.log(`  Script fetched: ${this.script.length} bytes`);
    }

    /**
     * Fetches the POW (Proof of Work) challenge from the server.
     * @returns {Promise<string>}
     */
    async _getPow() {
        const parsedUrl = new URL(this.config.targetUrl);
        const powUrl = `${parsedUrl.protocol}//${parsedUrl.host}${this.path}?d=${parsedUrl.host}`;
        const origin = `${parsedUrl.protocol}//${parsedUrl.host}`;

        // POW request body is hardcoded
        const powBody = '{"f":"gpc"}';

        const headers = {
            pragma: 'no-cache',
            'cache-control': 'no-cache',
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            accept: 'application/json; charset=utf-8',
            'sec-ch-ua': SEC_CH_UA,
            'content-type': 'text/plain; charset=utf-8',
            'sec-ch-ua-mobile': '?0',
            origin: origin,
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            referer: this.config.referer,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1, i',
        };

        const headerOrder = [
            'content-length',
            'pragma',
            'cache-control',
            'sec-ch-ua-platform',
            'user-agent',
            'accept',
            'sec-ch-ua',
            'content-type',
            'sec-ch-ua-mobile',
            'origin',
            'sec-fetch-site',
            'sec-fetch-mode',
            'sec-fetch-dest',
            'referer',
            'accept-encoding',
            'accept-language',
            'priority',
        ];

        const response = await this.session.post(powUrl, powBody, {
            headers,
            headerOrder,
        });

        // Response is a JSON string
        return JSON.parse(response.body);
    }

    /**
     * Calls the Hyper API to generate a Reese84 sensor.
     * @param {string} powValue
     * @returns {Promise<string>}
     */
    async _generateSensor(powValue) {
        const parsedUrl = new URL(this.config.targetUrl);
        const scriptUrl = `${parsedUrl.protocol}//${parsedUrl.host}${this.fullPath}`;

        const sensor = await generateReese84Sensor(
            this.hyperApi,
            new Reese84Input(
                USER_AGENT,
                this.ip,
                this.config.acceptLanguage,
                this.config.targetUrl,
                this.script,
                scriptUrl,
                powValue,
            )
        );

        return sensor;
    }

    /**
     * Posts the generated sensor to the Incapsula endpoint.
     * @param {string} sensor
     * @returns {Promise<void>}
     */
    async _submitSensor(sensor) {
        const parsedUrl = new URL(this.config.targetUrl);
        const sensorUrl = `${parsedUrl.protocol}//${parsedUrl.host}${this.path}?d=${parsedUrl.host}`;
        const origin = `${parsedUrl.protocol}//${parsedUrl.host}`;

        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            accept: 'application/json; charset=utf-8',
            'sec-ch-ua': SEC_CH_UA,
            'content-type': 'text/plain; charset=utf-8',
            'sec-ch-ua-mobile': '?0',
            origin: origin,
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            referer: this.config.referer,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=1, i',
        };

        const headerOrder = [
            'content-length',
            'sec-ch-ua-platform',
            'user-agent',
            'accept',
            'sec-ch-ua',
            'content-type',
            'sec-ch-ua-mobile',
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

        const response = await this.session.post(sensorUrl, sensor, {
            headers,
            headerOrder,
        });

        // Parse response to get the token
        const result = JSON.parse(response.body);

        const token = result.token || '';
        const cookieDomain = result.cookieDomain || '';

        if (!token) {
            throw new Error('No token received in sensor response');
        }

        // Set the reese84 cookie
        await this.session.addCookiesToSession(this.session.getSession(), sensorUrl, [
            {
                domain: cookieDomain,
                path: '/',
                name: 'reese84',
                value: token,
            },
        ]);

        console.log(`  Token received and cookie set: ${token.substring(0, 30)}...`);
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
            'sec-fetch-dest': 'document',
            referer: this.config.referer,
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
            priority: 'u=0, i',
        };

        const headerOrder = [
            'cache-control',
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

        const response = await this.session.get(this.config.targetUrl, {
            headers,
            headerOrder,
        });

        const body = response.body;

        // Check if we're still seeing the challenge page
        if (body.includes('Pardon Our Interruption')) {
            console.log(`Failed! Still seeing challenge page (HTTP ${response.status})`);
            return false;
        }

        const success = response.status === 200;
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
    config.targetUrl = 'https://digital.example.com/book';
    config.referer = 'https://digital.example.com/';
    config.cookieDomain = 'https://digital.example.com/';

    // Enable POW if required by the target site
    config.powEnabled = true;

    // Validate API key
    if (!config.apiKey) {
        console.error(
            'HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co'
        );
        process.exit(1);
    }

    // Create and run solver
    const solver = new Reese84Solver(config);
    try {
        const success = await solver.solve();

        if (success) {
            console.log('\n✅ Incapsula Reese84 bypass successful!');
            console.log('You can now make authenticated requests using the same session.');
        } else {
            console.log('\n❌ Incapsula Reese84 bypass failed.');
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

export { Reese84Solver, defaultConfig };