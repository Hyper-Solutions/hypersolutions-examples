// Package main is an example of the Akamai-BM-Telemetry flow with the Hyper Solutions SDK and
// the bogdanfinn/tls-client, against the resale shop on resale.paylogic.com.
//
// Some sites protect their API with an Akamai-BM-Telemetry header instead of sensor posts. The
// page loads the Bot Manager v3 script, the script fetches a "j" value from the site's
// get_params path, and every protected API call carries a fresh header. On paylogic the
// Angular app calls shopping-api.protected.paylogic.com cross-site without credentials, so the
// protected host never sees a cookie, only the header:
//
//	GET  resale page                         -> _abck, bm_sz, BM v3 script tag
//	GET  BM v3 script
//	     Hyper GetTelemetryParams            -> get_params path + context
//	GET  get_params path (same origin)       -> {"j": "..."}
//	     Hyper GenerateTelemetry per call    -> Akamai-BM-Telemetry, context chained
//	GET  protected /sales/<sale>             -> jwt_token
//	GET  protected /resale/<sale>            (Authorization: Bearer <jwt>)
//	GET  protected /ticket-transfer-approvals
//
// Each protected call is preceded by the CORS preflight a browser sends, since the telemetry
// header is not a simple header. The example only makes read-only requests: it never posts a
// basket, which would reserve a real ticket that cannot be released.
//
// For more information, visit: https://docs.hypersolutions.co
// Join our Discord community: https://discord.gg/akamai
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	hyper "github.com/Hyper-Solutions/hyper-sdk-go/v4"
)

// =============================================================================
// CONFIGURATION
// =============================================================================

const (
	// PageURL is the resale page: /<sale id>/<product category id>.
	PageURL = "https://resale.paylogic.com/04b83148045e477f9e3f14874e989a3c/5f2afb6b648245a5bf082d395f83635e"

	// Origin is the page's origin, the Origin of every API call.
	Origin = "https://resale.paylogic.com"

	// APIRoot is the unprotected API root the app loads first.
	APIRoot = "https://shopping-api.paylogic.com/"

	// ProtectedAPI is the host that checks the Akamai-BM-Telemetry header.
	ProtectedAPI = "https://shopping-api.protected.paylogic.com"

	// AcceptLanguage is the browser's accept-language header.
	AcceptLanguage = "en-US,en;q=0.9"

	// APILanguage is the Accept-Language the Angular app sets on its API calls.
	APILanguage = "en"

	// DefaultUserAgent is Chrome 152 on Windows, matching the TLS client profile.
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"

	// SecChUa and SecChUaPlatform are sent until the first generate call returns client hints.
	SecChUa         = `"Not=A?Brand";v="99", "Google Chrome";v="152", "Chromium";v="152"`
	SecChUaPlatform = `"Windows"`
)

// Config holds the settings that come from flags or the environment.
type Config struct {
	APIKey    string
	ProxyURL  string
	UserAgent string
	Timeout   time.Duration
}

func loadConfig() *Config {
	config := &Config{}
	flag.StringVar(&config.APIKey, "api-key", os.Getenv("HYPER_API_KEY"), "Hyper Solutions API key (env HYPER_API_KEY)")
	flag.StringVar(&config.ProxyURL, "proxy", os.Getenv("HTTP_PROXY"), "optional proxy URL (env HTTP_PROXY)")
	flag.StringVar(&config.UserAgent, "user-agent", envOr("USER_AGENT", DefaultUserAgent), "Chrome Windows user agent (env USER_AGENT)")
	flag.DurationVar(&config.Timeout, "timeout", 30*time.Second, "HTTP request timeout")
	flag.Parse()
	return config
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// scriptRegex matches the query-less BM v3 script tag. The page's SBSD script carries ?v=<uuid>
// and is not part of this flow.
var scriptRegex = regexp.MustCompile(`<script type="text/javascript"\s+src="(/[^"?]+)"`)

// =============================================================================
// HTTP CLIENTS
// =============================================================================

// createHTTPClient creates a Chrome TLS client. The page client has a cookie jar; the API client
// has none, because the app calls the protected host without credentials: no Cookie header goes
// out and its Set-Cookie headers are dropped.
func createHTTPClient(config *Config, withJar bool) (tlsclient.HttpClient, error) {
	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profiles.Chrome_152),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithTimeoutSeconds(int(config.Timeout.Seconds())),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithDisableHttp3(),
	}
	if withJar {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create cookie jar: %w", err)
		}
		options = append(options, tlsclient.WithCookieJar(jar))
	}
	if config.ProxyURL != "" {
		options = append(options, tlsclient.WithProxyUrl(config.ProxyURL))
	}

	client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS client: %w", err)
	}
	return client, nil
}

// =============================================================================
// TELEMETRY SOLVER
// =============================================================================

// TelemetrySolver runs the read-only part of the paylogic resale flow.
type TelemetrySolver struct {
	config    *Config
	client    tlsclient.HttpClient // page origin, with cookie jar
	apiClient tlsclient.HttpClient // protected API, no cookie jar
	hyperAPI  *hyper.Session

	ip              string
	saleID          string
	productCategory string

	scriptURL    string
	script       string
	j            string
	abck         string
	bmsz         string
	telemetryCtx string
	jwt          string

	// hints forwards the client hints of the latest telemetry call (see CLIENT HINTS)
	hints clientHints
}

// NewTelemetrySolver creates the clients and resolves the public IP.
func NewTelemetrySolver(ctx context.Context, config *Config) (*TelemetrySolver, error) {
	if config.APIKey == "" {
		return nil, errors.New("API key is required - get yours at https://hypersolutions.co")
	}

	pageURL, err := url.Parse(PageURL)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(pageURL.Path, "/"), "/")
	if len(parts) < 2 {
		return nil, errors.New("page URL must be /<sale>/<product category>")
	}

	client, err := createHTTPClient(config, true)
	if err != nil {
		return nil, err
	}
	apiClient, err := createHTTPClient(config, false)
	if err != nil {
		return nil, err
	}

	ip, err := getPublicIP(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP: %w", err)
	}
	log.Printf("Public IP: %s", ip)

	return &TelemetrySolver{
		config:          config,
		client:          client,
		apiClient:       apiClient,
		hyperAPI:        hyper.NewSession(config.APIKey),
		ip:              ip,
		saleID:          parts[0],
		productCategory: parts[1],
	}, nil
}

// Run loads the page, prepares the telemetry inputs and makes the protected calls.
func (s *TelemetrySolver) Run(ctx context.Context) error {
	log.Println("Step 1: Loading the resale page...")
	if err := s.getPage(ctx); err != nil {
		return err
	}

	log.Println("Step 2: Fetching the BM v3 script...")
	if err := s.getScript(ctx); err != nil {
		return err
	}

	log.Println("Step 3: Fetching j from get_params...")
	if err := s.getParams(ctx); err != nil {
		return err
	}

	log.Println("Step 4: Loading the API root...")
	if err := s.getAPIRoot(ctx); err != nil {
		return err
	}

	// The header is built from the page-load cookies. The protected host sets its own bm_sz,
	// but the browser drops it because the calls omit credentials.
	pageURL, _ := url.Parse(Origin)
	s.abck = getCookie(s.client, pageURL, "_abck")
	s.bmsz = getCookie(s.client, pageURL, "bm_sz")
	if s.abck == "" || s.bmsz == "" {
		return errors.New("missing _abck or bm_sz after the page load")
	}

	sleep(2500, 1500)

	log.Println("Step 5: Protected calls with Akamai-BM-Telemetry...")
	var sale struct {
		JwtToken string `json:"jwt_token"`
	}
	status, err := s.protected(ctx, "/sales/"+s.saleID, false, &sale)
	if err != nil {
		return err
	}
	if status != 200 || sale.JwtToken == "" {
		return fmt.Errorf("sales returned %d", status)
	}
	s.jwt = sale.JwtToken

	sleep(900, 400)
	if status, err = s.protected(ctx, "/resale/"+s.saleID, true, nil); err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("resale returned %d", status)
	}

	sleep(900, 400)
	saleURL := ProtectedAPI + "/sales/" + s.saleID
	approvalsPath := "/ticket-transfer-approvals?sale=" + saleURL + "&product_category=" + s.productCategory
	if status, err = s.protected(ctx, approvalsPath, false, nil); err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("ticket-transfer-approvals returned %d", status)
	}

	// The next step in a browser is POST /baskets, which reserves a real ticket. This example
	// deliberately stops here.
	return nil
}

// getPage loads the resale page, which sets _abck and bm_sz and embeds the BM v3 script tag.
func (s *TelemetrySolver) getPage(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", PageURL, nil)
	if err != nil {
		return err
	}
	req.Header = http.Header{
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {s.config.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {AcceptLanguage},
		http.HeaderOrderKey: {
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
			"user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
			"sec-fetch-dest", "accept-encoding", "accept-language", "cookie",
		},
		http.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}

	resp, body, err := do(s.client, req)
	if err != nil {
		return err
	}
	log.Printf("  page: %d", resp.StatusCode)
	if resp.StatusCode != 200 {
		return fmt.Errorf("page returned %d", resp.StatusCode)
	}
	s.hints.record(resp.Header)

	m := scriptRegex.FindSubmatch(body)
	if len(m) < 2 {
		return errors.New("BM v3 script tag not found")
	}
	s.scriptURL = Origin + string(m[1])
	log.Printf("  script: %s", s.scriptURL)
	return nil
}

// getScript downloads the BM v3 script.
func (s *TelemetrySolver) getScript(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.scriptURL, nil)
	if err != nil {
		return err
	}
	req.Header = http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {s.config.UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {AcceptLanguage},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "accept",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding",
			"accept-language", "cookie",
		},
		http.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}

	resp, body, err := do(s.client, req)
	if err != nil {
		return err
	}
	log.Printf("  script: %d (%d bytes)", resp.StatusCode, len(body))
	if resp.StatusCode != 200 {
		return fmt.Errorf("BM script returned %d", resp.StatusCode)
	}
	s.script = string(body)
	return nil
}

// getParams asks the Hyper API for the site's get_params path, then fetches it for "j". The
// returned context replaces the script on the first telemetry call.
func (s *TelemetrySolver) getParams(ctx context.Context) error {
	params, err := s.hyperAPI.GetTelemetryParams(ctx, &hyper.TelemetryParamsInput{
		PageUrl: PageURL,
		Script:  s.script,
	})
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}
	s.telemetryCtx = params.Context

	req, err := http.NewRequestWithContext(ctx, "GET", Origin+params.Path, nil)
	if err != nil {
		return err
	}
	req.Header = http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {s.config.UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {AcceptLanguage},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "accept",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding",
			"accept-language", "cookie",
		},
		http.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}

	resp, body, err := do(s.client, req)
	if err != nil {
		return err
	}
	log.Printf("  get_params: %d", resp.StatusCode)

	// Keep j verbatim: it goes into every telemetry call as returned.
	var result struct {
		J string `json:"j"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &result) != nil || result.J == "" {
		return fmt.Errorf("get_params returned %d: %.200s", resp.StatusCode, body)
	}
	s.j = result.J
	return nil
}

// getAPIRoot loads the unprotected API root, cross-site and without credentials like the app.
func (s *TelemetrySolver) getAPIRoot(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", APIRoot, nil)
	if err != nil {
		return err
	}
	req.Header = s.apiHeaders(false)

	resp, _, err := do(s.apiClient, req)
	if err != nil {
		return err
	}
	log.Printf("  api root: %d", resp.StatusCode)
	return nil
}

// apiHeaders is the Angular HttpClient header set in Chrome's order. The Authorization header
// shifts the order, so both variants are listed.
func (s *TelemetrySolver) apiHeaders(auth bool) http.Header {
	header := http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"accept-language":    {APILanguage},
		"accept":             {"application/json, text/plain, */*"},
		"sec-ch-ua":          {SecChUa},
		"user-agent":         {s.config.UserAgent},
		"sec-ch-ua-mobile":   {"?0"},
		"origin":             {Origin},
		"sec-fetch-site":     {"same-site"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		http.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}
	if auth {
		header[http.HeaderOrderKey] = []string{
			"akamai-bm-telemetry", "sec-ch-ua-platform", "authorization", "accept-language",
			"sec-ch-ua", "sec-ch-ua-mobile", "user-agent", "accept", "origin", "sec-fetch-site",
			"sec-fetch-mode", "sec-fetch-dest", "accept-encoding",
		}
	} else {
		header[http.HeaderOrderKey] = []string{
			"akamai-bm-telemetry", "sec-ch-ua-platform", "accept-language", "accept", "sec-ch-ua",
			"user-agent", "sec-ch-ua-mobile", "origin", "sec-fetch-site", "sec-fetch-mode",
			"sec-fetch-dest", "accept-encoding",
		}
	}
	s.hints.apply(header)
	return header
}

// protected sends the preflight, then a GET to the protected host with a fresh telemetry header,
// and decodes a 2xx JSON body into out when given.
func (s *TelemetrySolver) protected(ctx context.Context, path string, auth bool, out any) (int, error) {
	endpoint := ProtectedAPI + path
	label := strings.SplitN(strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0], "?", 2)[0]

	requestHeaders := "akamai-bm-telemetry"
	if auth {
		requestHeaders += ",authorization"
	}
	if err := s.preflight(ctx, endpoint, requestHeaders); err != nil {
		return 0, err
	}

	// Each call takes a fresh header built from the previous call's context. The first call
	// sends the get_params context instead of the script.
	res, err := s.hyperAPI.GenerateTelemetry(ctx, &hyper.TelemetryInput{
		SensorInput: hyper.SensorInput{
			Abck:           s.abck,
			Bmsz:           s.bmsz,
			PageUrl:        PageURL,
			ScriptUrl:      s.scriptURL,
			UserAgent:      s.config.UserAgent,
			AcceptLanguage: AcceptLanguage,
			IP:             s.ip,
			Context:        s.telemetryCtx,
		},
		J: s.j,
	})
	if err != nil {
		return 0, fmt.Errorf("Hyper API error: %w", err)
	}
	s.telemetryCtx = res.Context
	s.hints.update(res.ClientHints)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return 0, err
	}
	req.Header = s.apiHeaders(auth)
	req.Header["akamai-bm-telemetry"] = []string{res.Header}
	if auth {
		req.Header["authorization"] = []string{"Bearer " + s.jwt}
	}

	resp, body, err := do(s.apiClient, req)
	if err != nil {
		return 0, err
	}
	log.Printf("  %s: %d", label, resp.StatusCode)
	if resp.StatusCode >= 300 {
		log.Printf("    %.300s", body)
	}
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// preflight sends the CORS preflight Chrome makes before a request with non-simple headers.
func (s *TelemetrySolver) preflight(ctx context.Context, endpoint, requestHeaders string) error {
	req, err := http.NewRequestWithContext(ctx, "OPTIONS", endpoint, nil)
	if err != nil {
		return err
	}
	req.Header = http.Header{
		"accept":                         {"*/*"},
		"access-control-request-method":  {"GET"},
		"access-control-request-headers": {requestHeaders},
		"origin":                         {Origin},
		"user-agent":                     {s.config.UserAgent},
		"sec-fetch-mode":                 {"cors"},
		"sec-fetch-site":                 {"same-site"},
		"sec-fetch-dest":                 {"empty"},
		"accept-encoding":                {"gzip, deflate, br, zstd"},
		"accept-language":                {AcceptLanguage},
		http.HeaderOrderKey: {
			"accept", "access-control-request-method", "access-control-request-headers", "origin",
			"user-agent", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "accept-encoding",
			"accept-language",
		},
		http.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}

	resp, _, err := do(s.apiClient, req)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("preflight returned %d", resp.StatusCode)
	}
	return nil
}

// Close releases the clients' connections.
func (s *TelemetrySolver) Close() {
	s.client.CloseIdleConnections()
	s.apiClient.CloseIdleConnections()
}

// =============================================================================
// CLIENT HINTS
// =============================================================================

// clientHints forwards the client hints a Hyper generate call returned the way Chrome does.
// Chrome sends sec-ch-ua, sec-ch-ua-mobile and sec-ch-ua-platform on every request, and any other
// hint only to an origin that asked for it in an Accept-CH response header. Every request after
// a generate call here goes to the protected API, another origin than the page, so only the
// three default hints apply; the page's Accept-CH is recorded and logged for reference.
type clientHints struct {
	values   hyper.ClientHints // from the latest generate call, nil until one returned hints
	accepted []string          // lowercase hint names from the page's Accept-CH header
}

// record remembers the hints the page response asked for in Accept-CH.
func (c *clientHints) record(header http.Header) {
	for _, name := range strings.Split(header.Get("Accept-CH"), ",") {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			c.accepted = append(c.accepted, name)
		}
	}
	if len(c.accepted) > 0 {
		log.Printf("  page Accept-CH: %s", strings.Join(c.accepted, ", "))
	}
}

// update keeps the hints of a generate result for the following requests.
func (c *clientHints) update(values hyper.ClientHints) {
	if len(values) > 0 {
		c.values = values
	}
}

// apply replaces the hardcoded default hints with the generated ones on a cross-origin request.
func (c *clientHints) apply(header http.Header) {
	for _, name := range []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"} {
		if value, ok := c.values[name]; ok {
			header[name] = []string{value}
		}
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// do sends a request and reads the whole body.
func do(client tlsclient.HttpClient, req *http.Request) (*http.Response, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

// getCookie retrieves a cookie value by name from the client's cookie jar.
func getCookie(client tlsclient.HttpClient, u *url.URL, name string) string {
	for _, cookie := range client.GetCookies(u) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// getPublicIP retrieves the client's public IP address.
func getPublicIP(ctx context.Context, client tlsclient.HttpClient) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}
	_, body, err := do(client, req)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// sleep waits base milliseconds plus up to jitter more, like a user between actions.
func sleep(base, jitter int) {
	time.Sleep(time.Duration(base+rand.Intn(jitter+1)) * time.Millisecond)
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	config := loadConfig()
	if config.APIKey == "" {
		log.Fatal("HYPER_API_KEY environment variable (or -api-key) not set. Get your API key at https://hypersolutions.co")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	solver, err := NewTelemetrySolver(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create solver: %v", err)
	}
	defer solver.Close()

	if err := solver.Run(ctx); err != nil {
		log.Fatalf("Telemetry flow failed: %v", err)
	}
	fmt.Println("\nAll protected calls returned 200.")
}
