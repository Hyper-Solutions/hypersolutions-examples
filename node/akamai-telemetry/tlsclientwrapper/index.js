/**
 * Akamai-BM-Telemetry Example using tlsclientwrapper and Hyper Solutions SDK
 *
 * Some Akamai sites do not post sensor data. Their protected API calls carry an
 * Akamai-BM-Telemetry header instead, built from the same Bot Manager v3 script.
 * This example runs the read-only part of that flow on resale.paylogic.com:
 *
 *   1. GET the resale page: sets _abck and bm_sz and embeds the BM v3 script tag
 *   2. GET the BM v3 script
 *   3. getTelemetryParams returns the site's get_params path and a context;
 *      GET that path (same-origin) and keep the "j" of its JSON response verbatim
 *   4. Call the protected API (shopping-api.protected.paylogic.com). Every call
 *      takes a fresh header from generateTelemetry, chained from the previous
 *      call's context (the first call from the get_params context). The site's
 *      app calls that host cross-site without credentials: no cookies go there
 *      and its Set-Cookie is ignored. The header is not CORS-safelisted, so each
 *      call is preceded by the preflight a browser sends.
 *
 * Only GET endpoints are called. POST /baskets reserves a real ticket that
 * cannot be released, so this example never calls it.
 *
 * For more information, visit: https://docs.hypersolutions.co
 * Join our Discord community: https://discord.gg/akamai
 */

import { ModuleClient, SessionClient } from 'tlsclientwrapper';
import {
    Session as HyperSession,
    TelemetryInput,
    TelemetryParamsInput,
    generateTelemetry,
    getTelemetryParams,
} from 'hyper-sdk-js';

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Configuration for the Akamai-BM-Telemetry example.
 * @typedef {Object} Config
 * @property {string} apiKey - Your Hyper Solutions API key
 * @property {string} pageUrl - The resale page: https://resale.paylogic.com/<sale>/<product category>
 * @property {string} apiUrl - The protected API the page calls
 * @property {string} acceptLanguage - The browser's accept-language header
 * @property {string} apiAcceptLanguage - The accept-language the site's app sends on API calls
 * @property {string|null} proxyUrl - Optional HTTP/HTTPS/SOCKS5 proxy
 * @property {number} timeout - HTTP request timeout in seconds
 */

/**
 * Returns the configuration, read from the environment where set.
 * @returns {Config}
 */
function defaultConfig() {
    return {
        apiKey: process.env.HYPER_API_KEY || '',
        pageUrl:
            process.env.PAGE_URL ||
            'https://resale.paylogic.com/04b83148045e477f9e3f14874e989a3c/5f2afb6b648245a5bf082d395f83635e',
        apiUrl: 'https://shopping-api.protected.paylogic.com',
        acceptLanguage: 'en-US,en;q=0.9',
        apiAcceptLanguage: 'en',
        proxyUrl: process.env.HTTP_PROXY || null,
        timeout: 30,
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

// The BM v3 script tag has no query string (the SBSD tag carries ?v=<uuid>)
const SCRIPT_REGEX = /<script type="text\/javascript"\s+src="(\/[^"?]+)"/;

// =============================================================================
// CLIENT HINTS
// =============================================================================

// Client hints Chrome sends on every request. The others (sec-ch-ua-arch,
// sec-ch-ua-full-version-list, device-memory, ...) only go to an origin whose
// Accept-CH response header asked for them.
const DEFAULT_CLIENT_HINTS = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'];

/**
 * Reads a response header case-insensitively. The TLS client can return
 * canonical-case names and array values.
 * @param {{headers?: Object}} response
 * @param {string} name
 * @returns {string}
 */
function getResponseHeader(response, name) {
    const headers = response?.headers || {};
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
    if (key === undefined) {
        return '';
    }
    const value = headers[key];
    return Array.isArray(value) ? value.join(', ') : String(value);
}

/**
 * Forwards the client hints the Hyper API returns the way Chrome sends them.
 */
class ClientHints {
    constructor() {
        /** @type {Record<string, string>|null} Hints from the last generate call that returned them */
        this.hints = null;
        /** @type {Map<string, Set<string>>} Accept-CH hint names per origin */
        this.acceptCh = new Map();
    }

    /**
     * Stores the clientHints of a generate result. Results without hints keep
     * the previous ones.
     * @param {Record<string, string>|undefined} hints
     */
    update(hints) {
        if (hints) {
            this.hints = hints;
        }
    }

    /**
     * Records the Accept-CH header of a document response for its origin.
     * @param {string} url
     * @param {Object} response
     */
    recordAcceptCh(url, response) {
        const value = getResponseHeader(response, 'accept-ch');
        if (value) {
            const names = value.split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
            this.acceptCh.set(new URL(url).origin, new Set(names));
        }
    }

    /**
     * Sets the hints on a request: sec-ch-ua, sec-ch-ua-mobile and
     * sec-ch-ua-platform always, every other hint only when the request's
     * origin listed it in Accept-CH. Extra hints are ordered right after the
     * last sec-ch-* header. Before the first generate call the hardcoded
     * values stay.
     * @param {string} url
     * @param {Record<string, string>} headers
     * @param {string[]} headerOrder
     */
    apply(url, headers, headerOrder) {
        if (!this.hints) {
            return;
        }
        const allowed = this.acceptCh.get(new URL(url).origin) || new Set();
        const extra = [];
        for (const [name, value] of Object.entries(this.hints)) {
            if (DEFAULT_CLIENT_HINTS.includes(name) || allowed.has(name)) {
                headers[name] = value;
                if (!headerOrder.includes(name)) {
                    extra.push(name);
                }
            }
        }
        let at = -1;
        headerOrder.forEach((name, i) => {
            if (name.startsWith('sec-ch-')) {
                at = i;
            }
        });
        headerOrder.splice(at + 1, 0, ...extra);
    }
}

// =============================================================================
// TELEMETRY FLOW
// =============================================================================

/**
 * Runs the Akamai-BM-Telemetry flow against the read-only API endpoints.
 */
class TelemetryFlow {
    /**
     * @param {Config} config
     */
    constructor(config) {
        if (!config.apiKey) {
            throw new Error('API key is required - get yours at https://hypersolutions.co');
        }

        this.config = config;

        const parsedUrl = new URL(config.pageUrl);
        this.origin = parsedUrl.origin;
        const [saleId, productCategory] = parsedUrl.pathname.split('/').filter(Boolean);
        if (!saleId || !productCategory) {
            throw new Error('pageUrl must be https://resale.paylogic.com/<sale>/<product category>');
        }
        this.saleId = saleId;
        this.productCategory = productCategory;

        // Create ModuleClient for worker pool management
        this.moduleClient = new ModuleClient();

        // Create TLS client sessions with Chrome impersonation
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

        // The page session keeps the site's cookies (_abck, bm_sz, ...)
        this.session = new SessionClient(this.moduleClient, sessionOptions);

        // The API session has no cookie jar: the app's cross-site calls omit
        // credentials, so no Cookie header goes out and Set-Cookie is dropped
        this.apiSession = new SessionClient(this.moduleClient, {
            ...sessionOptions,
            withoutCookieJar: true,
        });

        // Create Hyper Solutions API session
        this.hyperApi = new HyperSession(config.apiKey);

        // Client hints from the Hyper API and the Accept-CH each origin asked for
        this.clientHints = new ClientHints();

        // Internal state
        this.ip = '';
        this.scriptUrl = '';
        this.script = '';
        this.j = '';
        this.abck = '';
        this.bmsz = '';
        this.telemetryContext = '';
        this.jwt = '';
        this.statuses = [];
    }

    /**
     * Runs the flow and records every status.
     * @returns {Promise<boolean>} True when every protected call returned 200.
     */
    async run() {
        this.ip = await this._getPublicIp();
        console.log(`Public IP: ${this.ip}`);

        console.log('Step 1: Fetching the resale page...');
        await this._fetchPage();

        console.log('Step 2: Fetching the BM v3 script...');
        await this._fetchScript();

        console.log('Step 3: Fetching the get_params "j"...');
        await this._fetchParams();

        // The header carries the page-load cookies. The protected host sets a
        // new bm_sz, but the browser drops it (credentials omitted).
        this.abck = await this._getCookie('_abck');
        this.bmsz = await this._getCookie('bm_sz');
        if (!this.abck || !this.bmsz) {
            throw new Error('Missing _abck or bm_sz after the page load');
        }

        console.log('Step 4: Calling the protected API...');
        await sleep(2500);

        // GET /sales/<sale> returns the jwt_token for the Bearer on /resale
        const sale = await this._protected(`/sales/${this.saleId}`, false);
        if (sale.status !== 200) {
            return false;
        }
        this.jwt = JSON.parse(sale.body).jwt_token || '';
        if (!this.jwt) {
            throw new Error('No jwt_token in the /sales response');
        }

        await sleep(900);
        const resale = await this._protected(`/resale/${this.saleId}`, true);
        if (resale.status !== 200) {
            return false;
        }

        await sleep(900);
        const saleUrl = `${this.config.apiUrl}/sales/${this.saleId}`;
        const approvals = await this._protected(
            `/ticket-transfer-approvals?sale=${saleUrl}&product_category=${this.productCategory}`,
            false
        );
        return approvals.status === 200;
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
     * Fetches the resale page and parses the BM v3 script tag.
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
        ];

        this.clientHints.apply(this.config.pageUrl, headers, headerOrder);
        const response = await this.session.get(this.config.pageUrl, {
            headers,
            headerOrder,
        });
        this._record('page', response.status);
        if (response.status !== 200) {
            throw new Error(`Page returned ${response.status}`);
        }
        this.clientHints.recordAcceptCh(this.config.pageUrl, response);

        const match = response.body.match(SCRIPT_REGEX);
        if (!match) {
            throw new Error('BM v3 script tag not found');
        }
        this.scriptUrl = this.origin + match[1];
        console.log(`  Script URL: ${this.scriptUrl}`);
    }

    /**
     * Fetches the BM v3 script.
     * @returns {Promise<void>}
     */
    async _fetchScript() {
        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'no-cors',
            'sec-fetch-dest': 'script',
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
            'accept-encoding',
            'accept-language',
            'cookie',
        ];

        this.clientHints.apply(this.scriptUrl, headers, headerOrder);
        const response = await this.session.get(this.scriptUrl, {
            headers,
            headerOrder,
        });
        this._record('script', response.status);
        if (response.status !== 200) {
            throw new Error(`Script returned ${response.status}`);
        }
        this.script = response.body;
        console.log(`  Script fetched: ${this.script.length} bytes`);
    }

    /**
     * Asks the Hyper API for the site's get_params path, then fetches it for
     * the "j" the telemetry header carries.
     * @returns {Promise<void>}
     */
    async _fetchParams() {
        const params = await getTelemetryParams(
            this.hyperApi,
            new TelemetryParamsInput(this.config.pageUrl, this.script)
        );
        // The params context replaces the script on the first telemetry request
        this.telemetryContext = params.context;
        console.log(`  get_params path: ${params.path}`);

        const paramsUrl = this.origin + params.path;

        const headers = {
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'user-agent': USER_AGENT,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            accept: '*/*',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
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
            'accept-encoding',
            'accept-language',
            'cookie',
        ];

        this.clientHints.apply(paramsUrl, headers, headerOrder);
        const response = await this.session.get(paramsUrl, {
            headers,
            headerOrder,
        });
        this._record('get_params', response.status);
        if (response.status !== 200) {
            throw new Error(`get_params returned ${response.status}`);
        }

        // "j" goes into TelemetryInput exactly as the site returned it
        this.j = JSON.parse(response.body).j || '';
        if (!this.j) {
            throw new Error('No "j" in the get_params response');
        }
    }

    /**
     * Builds the next Akamai-BM-Telemetry value, chained from the previous
     * context.
     * @returns {Promise<string>}
     */
    async _telemetry() {
        const result = await generateTelemetry(
            this.hyperApi,
            new TelemetryInput(
                this.abck,
                this.bmsz,
                this.config.pageUrl,
                USER_AGENT,
                this.ip,
                this.config.acceptLanguage,
                this.telemetryContext,
                // script: empty, the get_params context stands in for it
                '',
                this.scriptUrl,
                this.j
            )
        );
        this.telemetryContext = result.context;
        this.clientHints.update(result.clientHints);
        return result.header;
    }

    /**
     * Sends the CORS preflight a browser makes before a protected call.
     * @param {string} url
     * @param {boolean} auth - Whether the call carries an Authorization header
     * @returns {Promise<void>}
     */
    async _preflight(url, auth) {
        const headers = {
            accept: '*/*',
            'access-control-request-method': 'GET',
            'access-control-request-headers': auth ? 'akamai-bm-telemetry,authorization' : 'akamai-bm-telemetry',
            origin: this.origin,
            'user-agent': USER_AGENT,
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'sec-fetch-dest': 'empty',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': this.config.acceptLanguage,
        };

        const headerOrder = [
            'accept',
            'access-control-request-method',
            'access-control-request-headers',
            'origin',
            'user-agent',
            'sec-fetch-mode',
            'sec-fetch-site',
            'sec-fetch-dest',
            'accept-encoding',
            'accept-language',
        ];

        const response = await this.apiSession.options(url, {
            headers,
            headerOrder,
        });
        this._record('preflight', response.status);
    }

    /**
     * Calls the protected API with a fresh telemetry header.
     * @param {string} path
     * @param {boolean} auth - Send the jwt_token as a Bearer
     * @returns {Promise<{status: number, body: string}>}
     */
    async _protected(path, auth) {
        const url = this.config.apiUrl + path;
        await this._preflight(url, auth);

        const headers = {
            'akamai-bm-telemetry': await this._telemetry(),
            'sec-ch-ua-platform': SEC_CH_UA_PLATFORM,
            'accept-language': this.config.apiAcceptLanguage,
            accept: 'application/json, text/plain, */*',
            'sec-ch-ua': SEC_CH_UA,
            'user-agent': USER_AGENT,
            'sec-ch-ua-mobile': '?0',
            origin: this.origin,
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'accept-encoding': 'gzip, deflate, br, zstd',
        };

        // The site's app orders the headers differently once Authorization is set
        let headerOrder;
        if (auth) {
            headers.authorization = `Bearer ${this.jwt}`;
            headerOrder = [
                'akamai-bm-telemetry',
                'sec-ch-ua-platform',
                'authorization',
                'accept-language',
                'sec-ch-ua',
                'sec-ch-ua-mobile',
                'user-agent',
                'accept',
                'origin',
                'sec-fetch-site',
                'sec-fetch-mode',
                'sec-fetch-dest',
                'accept-encoding',
            ];
        } else {
            headerOrder = [
                'akamai-bm-telemetry',
                'sec-ch-ua-platform',
                'accept-language',
                'accept',
                'sec-ch-ua',
                'user-agent',
                'sec-ch-ua-mobile',
                'origin',
                'sec-fetch-site',
                'sec-fetch-mode',
                'sec-fetch-dest',
                'accept-encoding',
            ];
        }

        this.clientHints.apply(url, headers, headerOrder);
        const response = await this.apiSession.get(url, {
            headers,
            headerOrder,
        });

        const label = path.split(/[/?]/)[1];
        this._record(label, response.status);
        if (response.status !== 200) {
            console.log(`  ${label} body: ${response.body.substring(0, 300)}`);
        }
        return { status: response.status, body: response.body };
    }

    /**
     * Prints and stores a request's status.
     * @param {string} label
     * @param {number} status
     */
    _record(label, status) {
        console.log(`  ${label}: ${status}`);
        this.statuses.push(`${label}=${status}`);
    }

    /**
     * Retrieves a cookie value by name from the page session's cookie jar.
     * @param {string} name
     * @returns {Promise<string>}
     */
    async _getCookie(name) {
        try {
            const cookies = await this.session.getCookiesFromSession(this.session.getSession(), this.config.pageUrl);
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
     * Releases resources associated with the flow.
     * @returns {Promise<void>}
     */
    async close() {
        try {
            await this.session.destroySession();
            await this.apiSession.destroySession();
            await this.moduleClient.terminate();
        } catch {
            // Ignore cleanup errors
        }
    }
}

/**
 * Waits for the given number of milliseconds plus up to half of it again, so
 * the calls are spaced like a user's.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms + Math.random() * ms * 0.5));
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

async function main() {
    const config = defaultConfig();

    if (!config.apiKey) {
        console.error('HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co');
        process.exit(1);
    }

    const flow = new TelemetryFlow(config);
    try {
        const success = await flow.run();
        console.log(`\nStatuses: ${flow.statuses.join(' ')}`);

        if (success) {
            console.log('Every protected call returned 200.');
        } else {
            console.log('A protected call was refused.');
            process.exitCode = 1;
        }
    } catch (error) {
        console.error('Flow error:', error);
        process.exitCode = 1;
    } finally {
        await flow.close();
    }
}

main().catch(console.error);

export { TelemetryFlow, ClientHints, defaultConfig };
