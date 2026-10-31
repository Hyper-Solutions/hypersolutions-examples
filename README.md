# Hyper Solutions SDK Examples

Complete, working examples for bypassing modern bot protection systems using the [Hyper Solutions](https://hypersolutions.co) SDK.

[![Discord](https://dcbadge.limes.pink/api/server/akamai)](https://discord.gg/akamai)

## Supported Protections

| Protection | Description |
|------------|-------------|
| Akamai Bot Manager | Sensor data generation, SBSD challenges, cookie validation, Akamai-BM-Telemetry headers |
| DataDome | Interstitial challenges, slider captcha, tags/signal collection |
| Incapsula (Imperva) | Reese84 sensor generation, POW challenges |
| Kasada | Payload generation (CT), POW tokens (CD), BotID verification |

## Project Structure

```
├── golang/
│   ├── akamai/
│   │   ├── azuretls/
│   │   └── bogdanfinn/
│   ├── akamai-telemetry/
│   │   └── bogdanfinn/
│   ├── datadome/
│   │   ├── azuretls/
│   │   └── bogdanfinn/
│   ├── incapsula/
│   │   ├── azuretls/
│   │   └── bogdanfinn/
│   └── kasada/
│       ├── azuretls/
│       └── bogdanfinn/
│
├── node/
│   ├── akamai/
│   │   └── tlsclientwrapper/
│   ├── akamai-telemetry/
│   │   └── tlsclientwrapper/
│   ├── datadome/
│   │   └── tlsclientwrapper/
│   ├── incapsula/
│   │   └── tlsclientwrapper/
│   └── kasada/
│       └── tlsclientwrapper/
│
└── python/
    ├── akamai/
    │   ├── rnet/
    │   └── tls-client/
    ├── akamai-telemetry/
    │   └── tls-client/
    ├── datadome/
    │   ├── rnet/
    │   └── tls-client/
    ├── incapsula/
    │   ├── rnet/
    │   └── tls-client/
    └── kasada/
        ├── rnet/
        └── tls-client/
```

## Getting Started

### 1. Get Your API Key

Sign up at [hypersolutions.co](https://hypersolutions.co) to get your API key.

### 2. Set Environment Variable

```bash
export HYPER_API_KEY="your-api-key-here"
```

### 3. Run an Example

**Go (bogdanfinn/tls-client)**

```bash
cd golang/kasada/bogdanfinn
go mod tidy
go run main.go
```

**Node.js (tlsclientwrapper)**

```bash
cd node/kasada/tlsclientwrapper
npm install
node index.js
```

**Python (tls-client, synchronous)**

```bash
cd python/kasada/tls-client
pip install -r requirements.txt
python main.py
```

**Python (rnet, asynchronous)**

```bash
cd python/kasada/rnet
pip install -r requirements.txt
python main.py
```

## SDK Versions

The examples use the result-object SDK majors:

| SDK | Version |
|-----|---------|
| Go, `github.com/Hyper-Solutions/hyper-sdk-go/v4` | `v4.0.0` |
| Python, `hyper-sdk` | `4.0.0` |
| JS / TS, `hyper-sdk-js` | `5.0.0` |

Every generate call returns an object (`payload`, `context`, client hints, ...) instead of positional values.

## Dependencies

### Go

| Library | Description |
|---------|-------------|
| [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) | TLS client with browser fingerprint support |
| [Noooste/azuretls-client](https://github.com/Noooste/azuretls-client) | Alternative TLS client with Chrome fingerprinting |
| [Hyper-Solutions/hyper-sdk-go](https://github.com/Hyper-Solutions/hyper-sdk-go) | Hyper Solutions Go SDK |

### Node.js

| Library | Description |
|---------|-------------|
| [tlsclientwrapper](https://github.com/DemonMartin/tlsClient) | TLS client wrapper using Koffi bindings and worker pools |
| [hyper-sdk-js](https://www.npmjs.com/package/hyper-sdk-js) | Hyper Solutions JavaScript/TypeScript SDK |

### Python

| Library | Description |
|---------|-------------|
| [rnet](https://github.com/0x676e67/rnet) | Async TLS client with browser emulation (Rust-powered) |
| [Python-Tls-Client](https://github.com/Nintendocustom/Python-Tls-Client) | TLS client with browser impersonation |
| [hyper-sdk](https://pypi.org/project/hyper-sdk/) | Hyper Solutions Python SDK |

## Configuration

Each example includes a configuration object with the following common options:

| Option | Description |
|--------|-------------|
| `api_key` / `apiKey` | Your Hyper Solutions API key |
| `target_url` / `targetUrl` / `page_url` / `pageUrl` | The protected page URL |
| `proxy_url` / `proxyUrl` | Optional HTTP/HTTPS/SOCKS5 proxy |
| `accept_language` / `acceptLanguage` | Browser accept-language header |
| `timeout` | Request timeout duration |

Protection-specific options are documented in each example file.

## Example Flows

### Akamai Bot Manager

1. Fetch target page and detect protection (SBSD or sensor)
2. If SBSD detected: fetch script, generate payload, POST
3. Parse sensor endpoint from page
4. Fetch sensor script
5. Generate and POST sensor data (up to 3 times)
6. Validate `_abck` cookie

The first SBSD call sends the script and returns a context. Every SBSD call after it sends that
context and omits the script, since the API rejects a request carrying both. A hard block (an SBSD
POST with a `t` parameter) always starts a new chain: script, no context. Each SBSD call also sends
`scriptUrl`, the SBSD script's src exactly as the page loaded it.

### Akamai-BM-Telemetry (`akamai-telemetry/`)

Some sites protect their API with an `Akamai-BM-Telemetry` request header instead of a sensor post.
The examples run the flow on resale.paylogic.com, on read-only endpoints only:

1. Fetch the page and the Akamai script
2. Get the get_params path from the API, then request it once for `j`
3. Before every protected API call, generate a fresh header (chaining `context`) and send it as
   `Akamai-BM-Telemetry`

They never add a ticket to the basket: on Paylogic that reserves a real ticket that cannot be released.

### DataDome

1. Fetch target page to trigger DataDome
2. Detect challenge type (interstitial vs slider)
3. Fetch the challenge script if the page loads it from its own file instead of inlining it
4. If interstitial: fetch page, generate payload, POST
5. If slider: fetch captcha, download images, solve, submit
6. Optional: send tags requests for signal collection
7. Verify access

DataDome picks between inlining the challenge script and serving it from its own file per
request, so step 3 runs on every challenge. The SDK helper tells you which case you are in,
and you pass the script body to the API when there is one.

### Incapsula (Reese84)

1. Fetch target page to trigger challenge
2. Extract script paths from challenge page
3. Fetch Reese84 script
4. Optional: get POW challenge
5. Generate sensor via API
6. POST sensor to get token
7. Set `reese84` cookie and verify access

### Kasada

1. Fetch target page or `/fp` endpoint
2. Detect 429 response and extract `ips.js` URL
3. Fetch ips.js script
4. Generate payload via API (with `strict`, so the API refuses with an error instead of returning a payload when the script has a signal it cannot identify yet)
5. POST payload to `/tl` endpoint
6. Optional: solve BotID challenge
7. Generate POW (x-kpsdk-cd) for protected requests

## Client Hints

The generate calls return the Accept-CH client hints for the device the payload describes. The
examples send them the way Chrome does: `sec-ch-ua`, `sec-ch-ua-mobile` and `sec-ch-ua-platform`
always, every other hint only when the site asked for it in its `Accept-CH` response header. On
Kasada the hints are separate from the `x-kpsdk-*` headers, which always go on the request.

## Browser Fingerprinting

All examples use Chrome 143 fingerprints:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"
sec-ch-ua-platform: "Windows"
```

TLS fingerprints are configured to match Chrome 133 profile for consistency with the TLS client libraries.

## Important Notes

- **Header order matters.** All examples carefully maintain HTTP header order to match real browser behavior.
- **Cookie handling.** Examples use proper cookie jar management for session persistence.
- **IP consistency.** Your public IP is sent to the API for fingerprint consistency. Use the same proxy for all requests.
- **Node.js requirements.** The tlsclientwrapper requires Node.js 16+ and a platform supported by Koffi (Windows, macOS, Linux).

## Documentation

- [Hyper Solutions Docs](https://docs.hypersolutions.co)
- [Go SDK Reference](https://pkg.go.dev/github.com/Hyper-Solutions/hyper-sdk-go/v3)
- [JavaScript SDK (npm)](https://www.npmjs.com/package/hyper-sdk-js)
- [Python SDK (PyPI)](https://pypi.org/project/hyper-sdk/)
- [tlsclientwrapper](https://github.com/DemonMartin/tlsClient)
- [rnet](https://github.com/0x676e67/rnet)

## Support

- [Discord community](https://discord.gg/akamai)
- [GitHub Issues](https://github.com/Hyper-Solutions/hyper-sdk-examples/issues)
- [hypersolutions.co](https://hypersolutions.co)

## License

MIT License. See [LICENSE](LICENSE) for details.