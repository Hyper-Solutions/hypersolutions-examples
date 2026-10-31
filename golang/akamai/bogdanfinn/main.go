// Package main provides a complete example of bypassing Akamai Bot Manager protection
// using the Hyper Solutions SDK with the bogdanfinn/tls-client.
//
// This example demonstrates:
//   - Setting up a TLS client with proper browser fingerprinting
//   - Detecting and solving SBSD (State-Based Scraping Detection) challenges
//   - Handling SBSD with and without the "t" parameter (context-only chaining,
//     ScriptUrl is the script tag src exactly as the page loaded it)
//   - Generating and submitting sensor data via the Hyper API
//   - Cookie validation and the complete bypass flow
//   - Forwarding the client hints each generate call returns (sec-ch-ua and the
//     Accept-CH hints the site asked for) on the following requests
//
// For more information, visit: https://docs.hypersolutions.co
// Join our Discord community: https://discord.gg/akamai
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	hyper "github.com/Hyper-Solutions/hyper-sdk-go/v4"
	"github.com/Hyper-Solutions/hyper-sdk-go/v4/akamai"
)

// =============================================================================
// CONFIGURATION
// =============================================================================

// Config holds all configuration for the Akamai bypass example.
// Modify these values according to your target site and environment.
type Config struct {
	// APIKey is your Hyper Solutions API key.
	// Get yours at: https://hypersolutions.co
	APIKey string

	// TargetURL is the protected page you want to access.
	TargetURL string

	// Referer is the HTTP referer header value.
	// Usually the same as TargetURL or the base domain.
	Referer string

	// AcceptLanguage is the browser's accept-language header.
	// Should match your target region/language.
	AcceptLanguage string

	// ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
	// Leave empty to connect directly.
	ProxyURL string

	// Timeout is the HTTP request timeout duration.
	Timeout time.Duration

	// Version is the Akamai version (usually "2" or "3").
	Version string
}

// DefaultConfig returns a sensible default configuration.
// You MUST replace the APIKey and TargetURL with your own values.
func DefaultConfig() *Config {
	return &Config{
		APIKey:         os.Getenv("HYPER_API_KEY"), // Set via environment variable
		TargetURL:      "https://example.com/protected-page",
		Referer:        "https://example.com/",
		AcceptLanguage: "en-US,en;q=0.9",
		ProxyURL:       os.Getenv("HTTP_PROXY"), // Optional: set via environment variable
		Timeout:        30 * time.Second,
		Version:        "3", // Default to version 3
	}
}

// =============================================================================
// BROWSER FINGERPRINT CONSTANTS
// =============================================================================

// These constants define the browser fingerprint used for requests.
// They must match the TLS client profile (Chrome 152) to avoid detection.
const (
	// UserAgent is the browser user agent string for Chrome 152 on Windows.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

	// SecChUa is the sec-ch-ua header value for Chrome 152.
	SecChUa = `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`

	// SecChUaPlatform is the sec-ch-ua-platform header value.
	SecChUaPlatform = `"Windows"`
)

// =============================================================================
// SBSD DETECTION
// =============================================================================

// SbsdInfo holds extracted SBSD information from the page.
type SbsdInfo struct {
	Src  string // Script tag src as the page has it, query included
	Path string // Script path (e.g., /abc/def)
	Uuid string // UUID/version parameter
	T    string // Optional "t" parameter (indicates hardblock if present)
}

// sbsdRegex extracts SBSD script information from page HTML: the whole src, its path, the uuid and the
// optional t parameter.
var sbsdRegex = regexp.MustCompile(`(?i)["']((?:https?://[^/"']+)?([a-z\d/\-_\.]+)\?v=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:&[^"']*?\bt=([^"'&]+))?[^"']*)["']`)

// parseSbsdInfo attempts to extract SBSD information from page HTML.
// Returns nil if SBSD is not detected.
func parseSbsdInfo(page string) *SbsdInfo {
	matches := sbsdRegex.FindStringSubmatch(page)
	if len(matches) < 4 {
		return nil
	}

	return &SbsdInfo{
		Src:  html.UnescapeString(matches[1]), // &amp;t=... in the attribute is &t=... on the wire
		Path: matches[2],
		Uuid: matches[3],
		T:    matches[4],
	}
}

// IsHardblock returns true if SBSD is in hardblock mode (t parameter present).
func (s *SbsdInfo) IsHardblock() bool {
	return s.T != ""
}

// ScriptURL returns the absolute URL of the SBSD script exactly as the page loads it, query included
// (?v=<uuid>, plus &t=... on a hard block). It is both the URL to fetch and the ScriptUrl for the Hyper API.
func (s *SbsdInfo) ScriptURL(baseURL string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	src, err := url.Parse(s.Src)
	if err != nil {
		return "", err
	}

	return base.ResolveReference(src).String(), nil
}

// PostURL returns the URL for posting SBSD payloads.
func (s *SbsdInfo) PostURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	postURL := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, s.Path)
	if s.T != "" {
		postURL += "?t=" + s.T
	}

	return postURL, nil
}

// =============================================================================
// HTTP CLIENT SETUP
// =============================================================================

// createHTTPClient creates a new TLS client with proper browser fingerprinting.
func createHTTPClient(config *Config) (tlsclient.HttpClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	options := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profiles.Chrome_152),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithTimeoutSeconds(int(config.Timeout.Seconds())),
		tlsclient.WithRandomTLSExtensionOrder(),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDisableHttp3(),
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
// AKAMAI SOLVER
// =============================================================================

// AkamaiSolver handles the complete Akamai bypass flow.
type AkamaiSolver struct {
	config   *Config
	client   tlsclient.HttpClient
	hyperAPI *hyper.Session

	// Internal state
	ip             string
	pageHTML       string
	sbsdInfo       *SbsdInfo
	sbsdScript     string
	sbsdContext    string
	sensorScript   string
	sensorEndpoint string
	sensorContext  string

	// hints forwards the client hints of the latest generate call (see CLIENT HINTS)
	hints clientHints
}

// NewAkamaiSolver creates a new solver instance.
func NewAkamaiSolver(ctx context.Context, config *Config) (*AkamaiSolver, error) {
	if config.APIKey == "" {
		return nil, errors.New("API key is required - get yours at https://hypersolutions.co")
	}
	if config.TargetURL == "" {
		return nil, errors.New("target URL is required")
	}

	client, err := createHTTPClient(config)
	if err != nil {
		return nil, err
	}

	hyperAPI := hyper.NewSession(config.APIKey)

	ip, err := getPublicIP(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP: %w", err)
	}
	log.Printf("Public IP: %s", ip)

	return &AkamaiSolver{
		config:   config,
		client:   client,
		hyperAPI: hyperAPI,
		ip:       ip,
	}, nil
}

// Solve attempts to bypass Akamai protection and access the target page.
// Returns true if successful, false if blocked.
func (s *AkamaiSolver) Solve(ctx context.Context) (bool, error) {
	log.Println("Step 1: Making initial request to detect Akamai protection...")

	// Step 1: Fetch the page and detect protection type
	if err := s.fetchPage(ctx); err != nil {
		return false, fmt.Errorf("failed to fetch page: %w", err)
	}

	// Step 2: Handle SBSD if detected
	if s.sbsdInfo != nil {
		log.Printf("Step 2: SBSD detected (hardblock=%v), solving...", s.sbsdInfo.IsHardblock())
		if err := s.solveSbsd(ctx); err != nil {
			return false, fmt.Errorf("SBSD solve failed: %w", err)
		}
	} else {
		log.Println("Step 2: No SBSD detected, skipping...")
	}

	// Step 3: Handle sensor flow
	log.Println("Step 3: Starting sensor flow...")
	if err := s.parseSensorEndpoint(); err != nil {
		log.Println("  Sensor endpoint not found, skipping sensor posts")
		return true, nil
	}

	if err := s.fetchSensorScript(ctx); err != nil {
		return false, fmt.Errorf("failed to fetch sensor script: %w", err)
	}

	// Step 4: Submit sensors (up to 3 times)
	log.Println("Step 4: Submitting sensors...")
	for i := 0; i < 3; i++ {
		log.Printf("  Sensor attempt %d/3...", i+1)
		if err := s.postSensor(ctx, i); err != nil {
			return false, fmt.Errorf("sensor post %d failed: %w", i+1, err)
		}

		// Check if cookie is valid
		abck := s.getCookie("_abck")
		if akamai.IsCookieValid(abck, i) {
			log.Printf("  Cookie valid after %d sensor(s)!", i+1)
			return true, nil
		}
	}

	// Check final cookie state
	abck := s.getCookie("_abck")
	if !strings.Contains(abck, "~") {
		log.Println("Warning: Cookie doesn't contain stopping signal (~). Site may not use stopping signal, or cookie is invalid.")
	}

	return true, nil
}

// fetchPage makes a GET request to the target page and extracts protection info.
func (s *AkamaiSolver) fetchPage(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.TargetURL, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {s.config.AcceptLanguage},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
			"sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
			"accept-language", "priority",
		},
	}
	s.hints.apply(req.Header)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	s.pageHTML = string(body)
	s.hints.record(resp.Header)

	// Check for SBSD
	s.sbsdInfo = parseSbsdInfo(s.pageHTML)
	if s.sbsdInfo != nil {
		log.Printf("  SBSD detected: path=%s, uuid=%s, t=%s", s.sbsdInfo.Path, s.sbsdInfo.Uuid, s.sbsdInfo.T)
	}

	return nil
}

// solveSbsd handles the SBSD challenge flow.
func (s *AkamaiSolver) solveSbsd(ctx context.Context) error {
	// Fetch SBSD script
	log.Println("  Fetching SBSD script...")
	if err := s.fetchSbsdScript(ctx); err != nil {
		return err
	}

	if s.sbsdInfo.IsHardblock() {
		// Hardblock mode: post once, then reload page. A hard block always sends the script with an
		// empty context, never a context from an earlier request.
		log.Println("  Hardblock mode: posting single SBSD payload...")
		s.sbsdContext = ""
		if err := s.postSbsd(ctx); err != nil {
			return err
		}

		// Reload the page
		log.Println("  Reloading page after SBSD...")
		if err := s.fetchPage(ctx); err != nil {
			return err
		}
	} else {
		// Non-hardblock mode: post twice. The first payload is built from the script, the second
		// from the context the first call returned.
		log.Println("  Non-hardblock mode: posting two SBSD payloads...")
		if err := s.postSbsd(ctx); err != nil {
			return err
		}
		if err := s.postSbsd(ctx); err != nil {
			return err
		}
	}

	return nil
}

// fetchSbsdScript retrieves the SBSD script content.
func (s *AkamaiSolver) fetchSbsdScript(ctx context.Context) error {
	scriptURL, err := s.sbsdInfo.ScriptURL(s.config.TargetURL)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", scriptURL, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {s.config.TargetURL},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1"},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language", "cookie", "priority",
		},
	}
	s.hints.apply(req.Header)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	s.sbsdScript = string(body)
	log.Printf("  SBSD script fetched: %d bytes", len(s.sbsdScript))

	return nil
}

// postSbsd submits an SBSD payload.
func (s *AkamaiSolver) postSbsd(ctx context.Context) error {
	// Get the O cookie (bm_so or sbsd_o)
	oCookie := s.getCookie("bm_so")
	if oCookie == "" {
		oCookie = s.getCookie("sbsd_o")
	}

	scriptURL, err := s.sbsdInfo.ScriptURL(s.config.TargetURL)
	if err != nil {
		return err
	}

	input := &hyper.SbsdInput{
		UserAgent:      UserAgent,
		Uuid:           s.sbsdInfo.Uuid,
		PageUrl:        s.config.TargetURL,
		OCookie:        oCookie,
		ScriptUrl:      scriptURL,
		AcceptLanguage: s.config.AcceptLanguage,
		IP:             s.ip,
		Context:        s.sbsdContext,
	}

	// Script and context are mutually exclusive: the first request of a chain sends the script with an
	// empty context, later ones send the returned context
	if s.sbsdContext == "" {
		input.Script = s.sbsdScript
	}

	res, err := s.hyperAPI.GenerateSbsdData(ctx, input)
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}

	// Store context for subsequent requests, and the client hints for the next requests to the site
	s.sbsdContext = res.Context
	s.hints.update(res.ClientHints)

	postURL, err := s.sbsdInfo.PostURL(s.config.TargetURL)
	if err != nil {
		return err
	}

	// Wrap payload in JSON body
	bodyJSON, err := json.Marshal(map[string]string{"body": res.Payload})
	if err != nil {
		return err
	}

	targetURL, _ := url.Parse(s.config.TargetURL)

	req, err := http.NewRequestWithContext(ctx, "POST", postURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua":          {SecChUa},
		"content-type":       {"application/json"},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {UserAgent},
		"sec-ch-ua-platform": {SecChUaPlatform},
		"accept":             {"*/*"},
		"origin":             {fmt.Sprintf("%s://%s", targetURL.Scheme, targetURL.Host)},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {s.config.TargetURL},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
			"user-agent", "sec-ch-ua-platform", "accept", "origin",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie", "priority",
		},
	}
	s.hints.apply(req.Header)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return err
	}

	log.Println("  SBSD payload submitted")

	return nil
}

// parseSensorEndpoint extracts the sensor script endpoint from page HTML.
func (s *AkamaiSolver) parseSensorEndpoint() error {
	scriptPath, err := akamai.ParseScriptPath(strings.NewReader(s.pageHTML))
	if err != nil {
		return fmt.Errorf("failed to parse script path: %w", err)
	}

	targetURL, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return err
	}

	s.sensorEndpoint = fmt.Sprintf("%s://%s%s", targetURL.Scheme, targetURL.Host, scriptPath)
	log.Printf("  Sensor endpoint: %s", s.sensorEndpoint)

	return nil
}

// fetchSensorScript retrieves the Akamai sensor script content.
func (s *AkamaiSolver) fetchSensorScript(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.sensorEndpoint, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {UserAgent},
		"sec-ch-ua-platform": {SecChUaPlatform},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {s.config.TargetURL},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1"},
		http.HeaderOrderKey: {
			"sec-ch-ua", "sec-ch-ua-mobile", "user-agent", "sec-ch-ua-platform",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language", "cookie", "priority",
		},
	}
	s.hints.apply(req.Header)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	s.sensorScript = string(body)
	log.Printf("  Sensor script fetched: %d bytes", len(s.sensorScript))

	return nil
}

// postSensor submits sensor data to the Akamai endpoint.
func (s *AkamaiSolver) postSensor(ctx context.Context, iteration int) error {
	input := &hyper.SensorInput{
		Abck:           s.getCookie("_abck"),
		Bmsz:           s.getCookie("bm_sz"),
		Version:        s.config.Version,
		PageUrl:        s.config.TargetURL,
		UserAgent:      UserAgent,
		ScriptUrl:      s.sensorEndpoint,
		AcceptLanguage: s.config.AcceptLanguage,
		IP:             s.ip,
		Context:        s.sensorContext,
	}

	// Only include script on first sensor
	if iteration == 0 {
		input.Script = s.sensorScript
	}

	res, err := s.hyperAPI.GenerateSensorData(ctx, input)
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}

	// Store context for subsequent requests, and the client hints for the next requests to the site
	s.sensorContext = res.Context
	s.hints.update(res.ClientHints)

	// Wrap sensor data in JSON
	bodyJSON, err := json.Marshal(map[string]string{"sensor_data": res.Payload})
	if err != nil {
		return err
	}

	targetURL, _ := url.Parse(s.config.TargetURL)

	req, err := http.NewRequestWithContext(ctx, "POST", s.sensorEndpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-platform": {SecChUaPlatform},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {UserAgent},
		"content-type":       {"text/plain;charset=UTF-8"},
		"accept":             {"*/*"},
		"origin":             {fmt.Sprintf("%s://%s", targetURL.Scheme, targetURL.Host)},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {s.config.TargetURL},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length", "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile",
			"user-agent", "content-type", "accept", "origin",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie", "priority",
		},
	}
	s.hints.apply(req.Header)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

// getCookie retrieves a cookie value by name from the client's cookie jar.
func (s *AkamaiSolver) getCookie(name string) string {
	u, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return ""
	}

	cookies := s.client.GetCookies(u)
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}

	return ""
}

// Close releases resources associated with the solver.
func (s *AkamaiSolver) Close() {
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
}

// =============================================================================
// CLIENT HINTS
// =============================================================================

// clientHints forwards the client hints a Hyper generate call returned the way Chrome does:
// sec-ch-ua, sec-ch-ua-mobile and sec-ch-ua-platform on every request, any other hint only
// after the site asked for it in an Accept-CH response header.
type clientHints struct {
	values   hyper.ClientHints // from the latest generate call, nil until one returned hints
	accepted map[string]bool   // lowercase hint names from the site's Accept-CH header
}

// record remembers the hints a document response from the site asked for in Accept-CH.
func (c *clientHints) record(header http.Header) {
	for _, name := range strings.Split(header.Get("Accept-CH"), ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if c.accepted == nil {
			c.accepted = make(map[string]bool)
		}
		c.accepted[name] = true
	}
}

// update keeps the hints of a generate result for the following requests.
func (c *clientHints) update(values hyper.ClientHints) {
	if len(values) > 0 {
		c.values = values
	}
}

// apply sets the hints on a request to the site. The three default hints replace the hardcoded
// values; any other requested hint goes right after the last sec-ch-* header in the header order.
func (c *clientHints) apply(header http.Header) {
	var extra []string
	for name, value := range c.values {
		switch name {
		case "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform":
			header[name] = []string{value}
		default:
			if c.accepted[name] {
				header[name] = []string{value}
				extra = append(extra, name)
			}
		}
	}
	if len(extra) == 0 {
		return
	}
	sort.Strings(extra)

	order := header[http.HeaderOrderKey]
	at := len(order)
	for i, name := range order {
		if strings.HasPrefix(strings.ToLower(name), "sec-ch-") {
			at = i + 1
		}
	}
	newOrder := append(append(append([]string{}, order[:at]...), extra...), order[at:]...)
	header[http.HeaderOrderKey] = newOrder
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getPublicIP retrieves the client's public IP address.
func getPublicIP(ctx context.Context, client tlsclient.HttpClient) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	// Load configuration
	config := DefaultConfig()

	// Configure for your target site
	config.TargetURL = "https://www.example.com/us/en"
	config.Referer = "https://www.example.com/us/en"
	config.Version = "3" // Akamai version

	// Validate API key
	if config.APIKey == "" {
		log.Fatal("HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co")
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create solver
	solver, err := NewAkamaiSolver(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create solver: %v", err)
	}
	defer solver.Close()

	// Run the solver
	success, err := solver.Solve(ctx)
	if err != nil {
		log.Fatalf("Solver error: %v", err)
	}

	if success {
		fmt.Println("\n✅ Akamai bypass successful!")
		fmt.Println("You can now make authenticated requests using the same client.")
	} else {
		fmt.Println("\n❌ Akamai bypass failed.")
		fmt.Println("The IP may be blocked or additional challenges are required.")
		os.Exit(1)
	}
}
