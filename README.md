# Hyper Solutions SDK Examples

Complete, working examples for bypassing modern bot protection systems using the [Hyper Solutions](https://hypersolutions.co) SDK.

[![Discord](https://dcbadge.limes.pink/api/server/akamai)](https://discord.gg/akamai)

## Supported Protections

| Protection | Description |
|------------|-------------|
| Akamai Bot Manager | Sensor data generation, SBSD challenges, cookie validation |
| DataDome | Interstitial challenges, slider captcha, tags/signal collection |
| Incapsula (Imperva) | Reese84 sensor generation, POW challenges |
| Kasada | Payload generation (CT), POW tokens (CD), BotID verification |

## Project Structure

```
├── golang/
│   ├── akamai/
│   │   ├── azuretls/
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

### DataDome

1. Fetch target page to trigger DataDome
2. Detect challenge type (interstitial vs slider)
3. If interstitial: fetch page, generate payload, POST
4. If slider: fetch captcha, download images, solve, submit
5. Optional: send tags requests for signal collection
6. Verify access

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
4. Generate payload via API
5. POST payload to `/tl` endpoint
6. Optional: solve BotID challenge
7. Generate POW (x-kpsdk-cd) for protected requests

## Browser Fingerprinting

All examples use Chrome 143 fingerprints:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"
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
- [Go SDK Reference](https://pkg.go.dev/github.com/Hyper-Solutions/hyper-sdk-go/v2)
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