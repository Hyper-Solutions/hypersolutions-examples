// Package main provides a complete example of bypassing DataDome protection
// using the Hyper Solutions SDK with the bogdanfinn/tls-client.
//
// This example demonstrates:
//   - Setting up a TLS client with proper browser fingerprinting
//   - Detecting DataDome protection (interstitial vs slider captcha)
//   - Solving interstitial challenges
//   - Solving slider captcha challenges
//   - Solving tags challenges (signal collection)
//   - Handling the complete flow from initial request to successful bypass
//
// For more information, visit: https://docs.hypersolutions.co
// Join our Discord community: https://discord.gg/akamai
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	hyper "github.com/Hyper-Solutions/hyper-sdk-go/v2"
	"github.com/Hyper-Solutions/hyper-sdk-go/v2/datadome"
)

// =============================================================================
// CONFIGURATION
// =============================================================================

// Config holds all configuration for the DataDome bypass example.
// Modify these values according to your target site and environment.
type Config struct {
	// APIKey is your Hyper Solutions API key.
	// Get yours at: https://hypersolutions.co
	APIKey string

	// TargetURL is the protected page you want to access.
	TargetURL string

	// Referer is the HTTP referer header value.
	// Usually the base domain of the target site.
	Referer string

	// CookieDomain is the domain for storing the DataDome cookie.
	// Should match the target site's domain.
	CookieDomain string

	// AcceptLanguage is the browser's accept-language header.
	// Should match your target region/language.
	AcceptLanguage string

	// ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
	// Leave empty to connect directly.
	ProxyURL string

	// Timeout is the HTTP request timeout duration.
	Timeout time.Duration

	// ==========================================================================
	// TAGS CONFIGURATION (for signal collection)
	// ==========================================================================

	// TagsEnabled enables DataDome tags/signal collection after solving challenges.
	// This improves success rate on sites that require additional signals.
	TagsEnabled bool

	// TagsDDK is the DataDome key for the target site.
	// This is site-specific and can be found in the DataDome script URL or HTML.
	// Example: "13C44BAB4C9D728BBD66E2A9F0233B"
	TagsDDK string

	// TagsVersion is the DataDome tags version.
	// This should match the version used by the target site.
	TagsVersion string

	// TagsEndpoint is the DataDome tags collection endpoint.
	// Usually "https://datadome.example.com/js/" or similar.
	TagsEndpoint string
}

// DefaultConfig returns a sensible default configuration.
// You MUST replace the APIKey and TargetURL with your own values.
func DefaultConfig() *Config {
	return &Config{
		APIKey:         os.Getenv("HYPER_API_KEY"), // Set via environment variable
		TargetURL:      "https://example.com/protected-page",
		Referer:        "https://example.com/",
		CookieDomain:   "https://example.com/",
		AcceptLanguage: "en-US,en;q=0.9",
		ProxyURL:       os.Getenv("HTTP_PROXY"), // Optional: set via environment variable
		Timeout:        30 * time.Second,

		// Tags configuration (disabled by default)
		TagsEnabled:  false,
		TagsDDK:      "",
		TagsVersion:  "",
		TagsEndpoint: "https://datadome.example.com/js/",
	}
}

// =============================================================================
// BROWSER FINGERPRINT CONSTANTS
// =============================================================================

// These constants define the browser fingerprint used for requests.
// They must match the TLS client profile (Chrome 133) to avoid detection.
const (
	// UserAgent is the browser user agent string for Chrome 143 on Windows.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

	// SecChUa is the sec-ch-ua header value for Chrome 143.
	SecChUa = `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`

	// SecChUaPlatform is the sec-ch-ua-platform header value.
	SecChUaPlatform = `"Windows"`
)

// createHTTPClient creates a new TLS client with proper browser fingerprinting.
// The client is configured to:
//   - Use Chrome 133 TLS fingerprint
//   - Not follow redirects (to detect DataDome challenges)
//   - Use a cookie jar for session management
//   - Optionally use a proxy
func createHTTPClient(config *Config) (tlsclient.HttpClient, error) {
	// Create a cookie jar to store cookies across requests
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	// Build client options
	options := []tlsclient.HttpClientOption{
		// Use Chrome 133 TLS fingerprint - this must match your user agent
		tlsclient.WithClientProfile(profiles.Chrome_133),

		// Don't follow redirects - we need to detect DataDome challenge redirects
		tlsclient.WithNotFollowRedirects(),

		// Set request timeout
		tlsclient.WithTimeoutSeconds(int(config.Timeout.Seconds())),

		// Randomize TLS extension order for better fingerprint variation
		tlsclient.WithRandomTLSExtensionOrder(),

		// Use our cookie jar
		tlsclient.WithCookieJar(jar),

		// Disable http3 because most proxies don't support it yet
		tlsclient.WithDisableHttp3(),
	}

	// Add proxy if configured
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
// DATADOME SOLVER
// =============================================================================

// DataDomeSolver handles the complete DataDome bypass flow.
type DataDomeSolver struct {
	config   *Config
	client   tlsclient.HttpClient
	hyperAPI *hyper.Session

	// Internal state
	ip              string
	deviceCheckLink string
	html            string
	captchaPath     string
	isInterstitial  bool
}

// NewDataDomeSolver creates a new solver instance.
func NewDataDomeSolver(ctx context.Context, config *Config) (*DataDomeSolver, error) {
	// Validate configuration
	if config.APIKey == "" {
		return nil, errors.New("API key is required - get yours at https://hypersolutions.co")
	}
	if config.TargetURL == "" {
		return nil, errors.New("target URL is required")
	}

	// Validate tags configuration if enabled
	if config.TagsEnabled {
		if config.TagsDDK == "" {
			return nil, errors.New("TagsDDK is required when TagsEnabled is true")
		}
		if config.TagsVersion == "" {
			return nil, errors.New("TagsVersion is required when TagsEnabled is true")
		}
	}

	// Create HTTP client
	client, err := createHTTPClient(config)
	if err != nil {
		return nil, err
	}

	// Create Hyper Solutions API session
	hyperAPI := hyper.NewSession(config.APIKey)

	// Get public IP of proxy
	ip, err := getPublicIP(ctx, client)
	if err != nil {
		return nil, err
	}

	return &DataDomeSolver{
		config:   config,
		client:   client,
		hyperAPI: hyperAPI,
		ip:       ip,
	}, nil
}

// Solve attempts to bypass DataDome protection and access the target page.
// Returns true if successful, false if blocked.
func (s *DataDomeSolver) Solve(ctx context.Context) (bool, error) {
	log.Println("Step 1: Making initial request to detect DataDome protection...")

	// Step 1: Make initial request to trigger DataDome
	if err := s.makeInitialRequest(ctx); err != nil {
		return false, fmt.Errorf("initial request failed: %w", err)
	}

	// Step 2: Handle interstitial challenge if detected
	if s.isInterstitial {
		log.Println("Step 2: Detected interstitial challenge, solving...")
		if err := s.solveInterstitial(ctx); err != nil {
			return false, fmt.Errorf("interstitial solve failed: %w", err)
		}

		// After interstitial, reload the page to check if we need slider or are done
		log.Println("  Reloading page after interstitial...")
		if err := s.reloadPage(ctx); err != nil {
			return false, fmt.Errorf("reload after interstitial failed: %w", err)
		}
	}

	// Step 3: Handle slider captcha if needed (either directly or after interstitial)
	if !s.isInterstitial && s.deviceCheckLink != "" {
		log.Println("Step 3: Detected slider captcha, solving...")
		if err := s.solveSliderCaptcha(ctx); err != nil {
			return false, fmt.Errorf("slider captcha solve failed: %w", err)
		}

		// After slider, reload the page
		log.Println("  Reloading page after slider...")
		if err := s.reloadPage(ctx); err != nil {
			return false, fmt.Errorf("reload after slider failed: %w", err)
		}
	}

	// Step 4: Solve tags if enabled (signal collection for improved success rate)
	if s.config.TagsEnabled {
		log.Println("Step 4: Solving tags (signal collection)...")
		if err := s.solveTags(ctx); err != nil {
			return false, fmt.Errorf("tags solve failed: %w", err)
		}
	}

	// Step 5: Verify access to protected page
	log.Println("Step 5: Verifying access to protected page...")
	return s.verifyAccess(ctx)
}

// makeInitialRequest makes the first request to the target page.
// This triggers DataDome protection and allows us to detect the challenge type.
func (s *DataDomeSolver) makeInitialRequest(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.TargetURL, nil)
	if err != nil {
		return err
	}

	// Set headers that match a real Chrome browser
	// Header order is important for TLS fingerprinting!
	req.Header = http.Header{
		"Connection":                {"keep-alive"},
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {UserAgent},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":            {"none"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-User":            {"?1"},
		"Sec-Fetch-Dest":            {"document"},
		"Accept-Encoding":           {"gzip, deflate, br, zstd"},
		"Accept-Language":           {s.config.AcceptLanguage},
		http.HeaderOrderKey: {
			"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Get the DataDome cookie value
	ddCookie, err := s.getDataDomeCookie()
	if err != nil {
		return fmt.Errorf("failed to get datadome cookie: %w", err)
	}
	if ddCookie == "" {
		return errors.New("datadome cookie not found - site may not be protected or IP may be blocked")
	}

	log.Printf("DataDome cookie obtained: %s...", ddCookie[:min(20, len(ddCookie))])

	// Detect challenge type and parse device check link
	if bytes.Contains(body, []byte(`https://ct.captcha-delivery.com/i.js`)) {
		// Interstitial challenge detected
		s.isInterstitial = true
		s.deviceCheckLink, err = datadome.ParseInterstitialDeviceCheckLink(
			bytes.NewReader(body),
			ddCookie,
			s.config.TargetURL,
		)
		if err != nil {
			return fmt.Errorf("failed to parse interstitial device check link: %w", err)
		}
		log.Println("Challenge type: Interstitial")
	} else {
		// Slider captcha challenge
		s.isInterstitial = false
		s.deviceCheckLink, err = datadome.ParseSliderDeviceCheckLink(
			bytes.NewReader(body),
			ddCookie,
			s.config.TargetURL,
		)
		if err != nil {
			return fmt.Errorf("failed to parse slider device check link: %w", err)
		}
		log.Println("Challenge type: Slider Captcha")
	}

	return nil
}

// reloadPage reloads the target page after solving a challenge.
// This is necessary to get a fresh response and potentially detect additional challenges.
func (s *DataDomeSolver) reloadPage(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.TargetURL, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Connection":                {"keep-alive"},
		"Cache-Control":             {"max-age=0"},
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {UserAgent},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":            {"same-origin"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-User":            {"?1"},
		"Sec-Fetch-Dest":            {"document"},
		"Referer":                   {s.config.TargetURL},
		"Accept-Encoding":           {"gzip, deflate, br, zstd"},
		"Accept-Language":           {s.config.AcceptLanguage},
		http.HeaderOrderKey: {
			"Host", "Connection", "Cache-Control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Referer",
			"Accept-Encoding", "Accept-Language",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response body to check for additional challenges
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Check if we got another challenge (slider after interstitial)
	ddCookie, _ := s.getDataDomeCookie()

	if bytes.Contains(body, []byte(`captcha-delivery.com`)) {
		// Another challenge detected - parse the device check link
		s.deviceCheckLink, err = datadome.ParseSliderDeviceCheckLink(
			bytes.NewReader(body),
			ddCookie,
			s.config.TargetURL,
		)
		if err != nil {
			// If we can't parse slider, try interstitial
			s.deviceCheckLink, err = datadome.ParseInterstitialDeviceCheckLink(
				bytes.NewReader(body),
				ddCookie,
				s.config.TargetURL,
			)
			if err != nil {
				// No challenge found, we're good
				s.deviceCheckLink = ""
			} else {
				s.isInterstitial = true
				log.Println("  Additional interstitial challenge detected after reload")
			}
		} else {
			s.isInterstitial = false
			log.Println("  Additional slider challenge detected after reload")
		}
	} else {
		// No challenge, clear the device check link
		s.deviceCheckLink = ""
	}

	return nil
}

// solveInterstitial handles the interstitial challenge flow.
func (s *DataDomeSolver) solveInterstitial(ctx context.Context) error {
	// Step 2a: Fetch the interstitial page
	log.Println("  Fetching interstitial page...")
	if err := s.fetchInterstitialPage(ctx); err != nil {
		return err
	}

	// Step 2c: Generate interstitial payload using Hyper API
	log.Println("  Generating interstitial payload via Hyper API...")
	payload, _, err := s.hyperAPI.GenerateDataDomeInterstitial(ctx, &hyper.DataDomeInterstitialInput{
		UserAgent:      UserAgent,
		DeviceLink:     s.deviceCheckLink,
		Html:           s.html,
		IP:             s.ip,
		AcceptLanguage: s.config.AcceptLanguage,
	})
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}

	// Step 2d: Submit the interstitial payload
	log.Println("  Submitting interstitial solution...")
	return s.submitInterstitial(ctx, payload)
}

// fetchInterstitialPage retrieves the interstitial challenge HTML.
func (s *DataDomeSolver) fetchInterstitialPage(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.deviceCheckLink, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Connection":                {"keep-alive"},
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {UserAgent},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":            {"cross-site"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Dest":            {"iframe"},
		"Sec-Fetch-Storage-Access":  {"none"},
		"Referer":                   {s.config.Referer},
		"Accept-Encoding":           {"gzip, deflate, br, zstd"},
		"Accept-Language":           {s.config.AcceptLanguage},
		http.HeaderOrderKey: {
			"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Storage-Access", "Referer",
			"Accept-Encoding", "Accept-Language",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	s.html = string(body)
	return nil
}

// submitInterstitial posts the generated payload to solve the interstitial.
func (s *DataDomeSolver) submitInterstitial(ctx context.Context, payload string) error {
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://geo.captcha-delivery.com/interstitial/",
		strings.NewReader(payload))
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Connection":               {"keep-alive"},
		"sec-ch-ua-platform":       {SecChUaPlatform},
		"User-Agent":               {UserAgent},
		"sec-ch-ua":                {SecChUa},
		"Content-Type":             {"application/x-www-form-urlencoded; charset=UTF-8"},
		"sec-ch-ua-mobile":         {"?0"},
		"Accept":                   {"*/*"},
		"Origin":                   {"https://geo.captcha-delivery.com"},
		"Sec-Fetch-Site":           {"same-origin"},
		"Sec-Fetch-Mode":           {"cors"},
		"Sec-Fetch-Dest":           {"empty"},
		"Sec-Fetch-Storage-Access": {"none"},
		"Referer":                  {s.deviceCheckLink},
		"Accept-Encoding":          {"gzip, deflate, br, zstd"},
		"Accept-Language":          {s.config.AcceptLanguage},
		http.HeaderOrderKey: {
			"Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent",
			"sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Accept", "Origin",
			"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Storage-Access",
			"Referer", "Accept-Encoding", "Accept-Language",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response
	var result struct {
		Cookie string `json:"cookie"`
		View   string `json:"view"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse interstitial response: %w", err)
	}

	// Store the new cookie
	if result.Cookie != "" {
		s.setDataDomeCookie(result.Cookie)
	}

	log.Printf("  Interstitial result: view=%s", result.View)

	// Mark that we're no longer in interstitial mode
	// The reloadPage will detect if there's a slider captcha
	s.isInterstitial = false
	s.deviceCheckLink = ""

	return nil
}

// solveSliderCaptcha handles the slider captcha challenge flow.
func (s *DataDomeSolver) solveSliderCaptcha(ctx context.Context) error {
	// Step 3a: Fetch the captcha page
	log.Println("  Fetching captcha page...")
	if err := s.fetchCaptchaPage(ctx); err != nil {
		return err
	}

	// Step 3b: Download puzzle images
	log.Println("  Downloading puzzle images...")
	puzzle, err := s.downloadPuzzleImage(ctx)
	if err != nil {
		return err
	}

	piece, err := s.downloadPieceImage(ctx)
	if err != nil {
		return err
	}

	// Step 3d: Generate slider solution using Hyper API
	log.Println("  Generating slider solution via Hyper API...")
	checkURL, _, err := s.hyperAPI.GenerateDataDomeSlider(ctx, &hyper.DataDomeSliderInput{
		UserAgent:      UserAgent,
		DeviceLink:     s.deviceCheckLink,
		Html:           s.html,
		Puzzle:         base64.StdEncoding.EncodeToString(puzzle),
		Piece:          base64.StdEncoding.EncodeToString(piece),
		IP:             s.ip,
		AcceptLanguage: s.config.AcceptLanguage,
	})
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}

	// Step 3e: Submit the slider solution
	log.Println("  Submitting slider solution...")
	return s.submitSliderSolution(ctx, checkURL)
}

// fetchCaptchaPage retrieves the slider captcha HTML.
func (s *DataDomeSolver) fetchCaptchaPage(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", s.deviceCheckLink, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Connection":                {"keep-alive"},
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {UserAgent},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":            {"same-origin"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Dest":            {"iframe"},
		"Sec-Fetch-Storage-Access":  {"none"},
		"Referer":                   {s.config.Referer},
		"Accept-Encoding":           {"gzip, deflate, br, zstd"},
		"Accept-Language":           {s.config.AcceptLanguage},
		http.HeaderOrderKey: {
			"Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Storage-Access", "Referer",
			"Accept-Encoding", "Accept-Language",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	s.html = string(body)

	// Extract the captcha challenge path from the HTML
	re := regexp.MustCompile(`captchaChallengePath:\s*'(.*?)'`)
	matches := re.FindStringSubmatch(s.html)
	if len(matches) < 2 {
		return errors.New("captcha challenge path not found in HTML")
	}

	s.captchaPath = matches[1]
	log.Printf("  Captcha path: %s", s.captchaPath)

	return nil
}

// downloadPuzzleImage downloads the main puzzle background image.
func (s *DataDomeSolver) downloadPuzzleImage(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.captchaPath, nil)
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"Origin":             {"https://geo.captcha-delivery.com"},
		"sec-ch-ua-platform": {SecChUaPlatform},
		"User-Agent":         {UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"Accept":             {"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
		"Sec-Fetch-Site":     {"same-site"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"image"},
		"Referer":            {"https://geo.captcha-delivery.com/"},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {s.config.AcceptLanguage},
		"Priority":           {"i"},
		http.HeaderOrderKey: {
			"Origin", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer",
			"Accept-Encoding", "Accept-Language", "Priority",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// downloadPieceImage downloads the slider piece image.
func (s *DataDomeSolver) downloadPieceImage(ctx context.Context) ([]byte, error) {
	// The piece image URL is derived from the puzzle URL by replacing .jpg with .frag.png
	pieceURL := strings.Replace(s.captchaPath, ".jpg", ".frag.png", 1)

	req, err := http.NewRequestWithContext(ctx, "GET", pieceURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header = http.Header{
		"Origin":             {"https://geo.captcha-delivery.com"},
		"sec-ch-ua-platform": {SecChUaPlatform},
		"User-Agent":         {UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"Accept":             {"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
		"Sec-Fetch-Site":     {"same-site"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"image"},
		"Referer":            {"https://geo.captcha-delivery.com/"},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {s.config.AcceptLanguage},
		"Priority":           {"i"},
		http.HeaderOrderKey: {
			"Origin", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer",
			"Accept-Encoding", "Accept-Language", "Priority",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// submitSliderSolution submits the generated slider solution.
func (s *DataDomeSolver) submitSliderSolution(ctx context.Context, checkURL string) error {
	// The checkURL from the Hyper API is a complete URL that we GET to verify the solution
	req, err := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"Connection":               {"keep-alive"},
		"sec-ch-ua-platform":       {SecChUaPlatform},
		"User-Agent":               {UserAgent},
		"sec-ch-ua":                {SecChUa},
		"Content-Type":             {"application/x-www-form-urlencoded; charset=UTF-8"},
		"sec-ch-ua-mobile":         {"?0"},
		"Accept":                   {"*/*"},
		"Sec-Fetch-Site":           {"same-origin"},
		"Sec-Fetch-Mode":           {"cors"},
		"Sec-Fetch-Dest":           {"empty"},
		"Sec-Fetch-Storage-Access": {"none"},
		"Referer":                  {s.deviceCheckLink},
		"Accept-Encoding":          {"gzip, deflate, br, zstd"},
		"Accept-Language":          {s.config.AcceptLanguage},
		http.HeaderOrderKey: {
			"Host", "Connection", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua",
			"Content-Type", "sec-ch-ua-mobile", "Accept", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-Storage-Access", "Referer",
			"Accept-Encoding", "Accept-Language",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for block (HTTP 403 means failed verification)
	if resp.StatusCode == 403 {
		return errors.New("slider solution was rejected - captcha verification failed")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response to get the new cookie
	var result struct {
		Cookie string `json:"cookie"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse slider response: %w", err)
	}

	// Store the new cookie
	if result.Cookie != "" {
		s.setDataDomeCookie(result.Cookie)
		log.Println("  Slider captcha solved successfully!")
	}

	// Clear device check link since we've solved the captcha
	s.deviceCheckLink = ""

	return nil
}

// =============================================================================
// TAGS SOLVING (Signal Collection)
// =============================================================================

// solveTags handles the DataDome tags/signal collection flow.
// This sends two "tags" requests with a delay between them to improve success rate.
// Tags are used by DataDome to collect browser signals and validate real user behavior.
func (s *DataDomeSolver) solveTags(ctx context.Context) error {
	// Get current DataDome cookie
	cid, err := s.getDataDomeCookie()
	if err != nil {
		return fmt.Errorf("failed to get datadome cookie: %w", err)
	}
	if cid == "" {
		return errors.New("datadome cookie not found for tags")
	}

	// ==========================================================================
	// First tags request: "ch" (challenge) type
	// ==========================================================================
	log.Println("  Sending first tags request (type: ch)...")
	chPayload, err := s.hyperAPI.GenerateDataDomeTags(ctx, &hyper.DataDomeTagsInput{
		UserAgent:      UserAgent,
		Cid:            cid,
		Ddk:            s.config.TagsDDK,
		Referer:        s.config.Referer,
		Type:           "ch",
		IP:             s.ip,
		Version:        s.config.TagsVersion,
		AcceptLanguage: s.config.AcceptLanguage,
	})
	if err != nil {
		return fmt.Errorf("failed to generate ch tags payload: %w", err)
	}

	if err := s.postTags(ctx, chPayload); err != nil {
		return fmt.Errorf("failed to post ch tags: %w", err)
	}

	// ==========================================================================
	// Sleep between requests to simulate real user behavior
	// ==========================================================================
	log.Println("  Waiting 5 seconds before second tags request...")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
	}

	// ==========================================================================
	// Second tags request: "le" (loaded events) type
	// Refresh the cookie as it may have been updated
	// ==========================================================================
	cid, err = s.getDataDomeCookie()
	if err != nil {
		return fmt.Errorf("failed to get datadome cookie: %w", err)
	}

	log.Println("  Sending second tags request (type: le)...")
	lePayload, err := s.hyperAPI.GenerateDataDomeTags(ctx, &hyper.DataDomeTagsInput{
		UserAgent:      UserAgent,
		Cid:            cid,
		Ddk:            s.config.TagsDDK,
		Referer:        s.config.Referer,
		Type:           "le",
		IP:             s.ip,
		Version:        s.config.TagsVersion,
		AcceptLanguage: s.config.AcceptLanguage,
	})
	if err != nil {
		return fmt.Errorf("failed to generate le tags payload: %w", err)
	}

	if err := s.postTags(ctx, lePayload); err != nil {
		return fmt.Errorf("failed to post le tags: %w", err)
	}

	log.Println("  Tags solved successfully!")
	return nil
}

// postTags sends a tags payload to the DataDome tags endpoint.
func (s *DataDomeSolver) postTags(ctx context.Context, payload string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", s.config.TagsEndpoint, strings.NewReader(payload))
	if err != nil {
		return err
	}

	// Extract origin from referer for the Origin header
	refererURL, _ := url.Parse(s.config.Referer)
	origin := fmt.Sprintf("%s://%s", refererURL.Scheme, refererURL.Host)

	req.Header = http.Header{
		"sec-ch-ua":          {SecChUa},
		"Content-Type":       {"application/x-www-form-urlencoded"},
		"sec-ch-ua-mobile":   {"?0"},
		"User-Agent":         {UserAgent},
		"sec-ch-ua-platform": {SecChUaPlatform},
		"Accept":             {"*/*"},
		"Origin":             {origin},
		"Sec-Fetch-Site":     {"cross-site"},
		"Sec-Fetch-Mode":     {"cors"},
		"Sec-Fetch-Dest":     {"empty"},
		"Referer":            {s.config.Referer},
		"Accept-Encoding":    {"gzip, deflate, br, zstd"},
		"Accept-Language":    {s.config.AcceptLanguage},
		"Priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"Content-Length", "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile",
			"User-Agent", "sec-ch-ua-platform", "Accept", "Origin",
			"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer",
			"Accept-Encoding", "Accept-Language", "Priority",
		},
		http.PHeaderOrderKey: {":method", ":authority", ":scheme", ":path"},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse the response to get the updated cookie
	var result struct {
		Cookie string `json:"cookie"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse tags response: %w", err)
	}

	// Update cookie if provided
	if result.Cookie != "" {
		s.setDataDomeCookie(result.Cookie)
	}

	return nil
}

// verifyAccess makes a final request to verify we can access the protected page.
func (s *DataDomeSolver) verifyAccess(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.TargetURL, nil)
	if err != nil {
		return false, err
	}

	req.Header = http.Header{
		"Cache-Control":             {"max-age=0"},
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {UserAgent},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Sec-Fetch-Site":            {"same-origin"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-User":            {"?1"},
		"Sec-Fetch-Dest":            {"document"},
		"Referer":                   {s.config.TargetURL},
		"Accept-Encoding":           {"gzip, deflate, br, zstd"},
		"Accept-Language":           {s.config.AcceptLanguage},
		"Priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"Host", "Cache-Control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site",
			"Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Referer",
			"Accept-Encoding", "Accept-Language", "Cookie", "Priority",
		},
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Drain the response body
	io.Copy(io.Discard, resp.Body)

	success := resp.StatusCode != 403
	if success {
		log.Printf("Success! Access granted (HTTP %d)", resp.StatusCode)
	} else {
		log.Printf("Failed! Access denied (HTTP %d)", resp.StatusCode)
	}

	return success, nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getDataDomeCookie retrieves the current DataDome cookie value.
func (s *DataDomeSolver) getDataDomeCookie() (string, error) {
	u, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return "", err
	}

	cookies := s.client.GetCookies(u)
	for _, cookie := range cookies {
		if cookie.Name == "datadome" {
			return cookie.Value, nil
		}
	}

	return "", nil
}

// setDataDomeCookie updates the DataDome cookie in the client's cookie jar.
func (s *DataDomeSolver) setDataDomeCookie(cookieHeader string) {
	// Parse the Set-Cookie header
	header := http.Header{}
	header.Add("Set-Cookie", cookieHeader)
	response := http.Response{Header: header}
	cookies := response.Cookies()

	// Set cookies on the cookie domain
	u, _ := url.Parse(s.config.CookieDomain)
	s.client.SetCookies(u, cookies)
}

// getPublicIP retrieves the client's public IP address.
// This is required for generating valid DataDome payloads.
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

// Close releases resources associated with the solver.
func (s *DataDomeSolver) Close() {
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	// Load configuration
	config := DefaultConfig()

	config.TargetURL = "https://tickets.example.com/"
	config.Referer = "https://tickets.example.com/"
	config.CookieDomain = "https://example.com/"

	// Enable tags solving for improved success rate
	config.TagsEnabled = true
	config.TagsDDK = "EXAMPLEDDK" // Site-specific DataDome key
	config.TagsVersion = "5.1.13" // DataDome tags version
	config.TagsEndpoint = "https://datadome.example.com/js/"

	// Validate API key
	if config.APIKey == "" {
		log.Fatal("HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co")
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create solver
	solver, err := NewDataDomeSolver(ctx, config)
	if err != nil {
		log.Fatalf("Failed to create solver: %v", err)
	}
	defer solver.Close()

	success, err := solver.Solve(ctx)
	if err != nil {
		log.Fatalf("Solver error: %v", err)
	}

	if success {
		fmt.Println("\n✅ DataDome bypass successful!")
		fmt.Println("You can now make authenticated requests using the same client.")
	} else {
		fmt.Println("\n❌ DataDome bypass failed.")
		fmt.Println("The IP may be blocked or additional challenges are required.")
		os.Exit(1)
	}
}
