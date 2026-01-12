// Package main provides a complete example of bypassing Incapsula Reese84 protection
// using the Hyper Solutions SDK with the Noooste/azuretls-client.
//
// This example demonstrates:
//   - Setting up an AzureTLS client with proper browser fingerprinting
//   - Detecting Incapsula protection and extracting script paths
//   - Fetching the Reese84 script content
//   - Handling POW (Proof of Work) challenges when required
//   - Generating and submitting Reese84 sensors via the Hyper API
//   - Handling the complete flow from initial request to successful bypass
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
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"

	hyper "github.com/Hyper-Solutions/hyper-sdk-go/v2"
)

// =============================================================================
// CONFIGURATION
// =============================================================================

// Config holds all configuration for the Incapsula Reese84 bypass example.
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

	// CookieDomain is the domain for storing the Reese84 cookie.
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
	// POW CONFIGURATION (Proof of Work)
	// ==========================================================================

	// PowEnabled enables POW challenge solving.
	// Some sites require an additional POW step before sensor submission.
	PowEnabled bool
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
		PowEnabled:     false,
	}
}

// =============================================================================
// BROWSER FINGERPRINT CONSTANTS
// =============================================================================

// These constants define the browser fingerprint used for requests.
// They must match the TLS client profile (Chrome) to avoid detection.
const (
	// UserAgent is the browser user agent string for Chrome 143 on Windows.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"

	// SecChUa is the sec-ch-ua header value for Chrome 143.
	SecChUa = `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`

	// SecChUaPlatform is the sec-ch-ua-platform header value.
	SecChUaPlatform = `"Windows"`
)

// =============================================================================
// INCAPSULA REESE84 SOLVER
// =============================================================================

// Reese84Solver handles the complete Incapsula Reese84 bypass flow.
type Reese84Solver struct {
	config   *Config
	session  *azuretls.Session
	hyperAPI *hyper.Session

	// Internal state
	ip       string
	path     string // Script path for sensor POST endpoint (e.g., /abc123/def456)
	fullPath string // Full script path with query params for fetching
	script   string // Full Reese84 script content
}

// NewReese84Solver creates a new solver instance.
func NewReese84Solver(ctx context.Context, config *Config) (*Reese84Solver, error) {
	// Validate configuration
	if config.APIKey == "" {
		return nil, errors.New("API key is required - get yours at https://hypersolutions.co")
	}
	if config.TargetURL == "" {
		return nil, errors.New("target URL is required")
	}

	// Create AzureTLS session with context
	session := azuretls.NewSessionWithContext(ctx)

	// Set timeout
	session.SetTimeout(config.Timeout)

	// Pin manager doesn't work with HTTP debuggers, recommended to enable in production
	session.InsecureSkipVerify = true

	// Use Chrome browser fingerprint - this automatically sets up TLS and HTTP/2 fingerprints
	session.GetClientHelloSpec = azuretls.GetLastChromeVersion

	// Configure to not follow redirects - we need to detect Incapsula challenge redirects
	session.MaxRedirects = 0

	// Add proxy if configured
	if config.ProxyURL != "" {
		if err := session.SetProxy(config.ProxyURL); err != nil {
			return nil, fmt.Errorf("failed to set proxy: %w", err)
		}
	}

	// Create Hyper Solutions API session
	hyperAPI := hyper.NewSession(config.APIKey)

	// Get public IP (required for sensor generation)
	ip, err := getPublicIP(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP: %w", err)
	}
	log.Printf("Public IP: %s", ip)

	return &Reese84Solver{
		config:   config,
		session:  session,
		hyperAPI: hyperAPI,
		ip:       ip,
	}, nil
}

// Solve attempts to bypass Incapsula Reese84 protection and access the target page.
// Returns true if successful, false if blocked.
func (s *Reese84Solver) Solve(ctx context.Context) (bool, error) {
	log.Println("Step 1: Making initial request to detect Incapsula protection...")

	// Step 1: Make initial request to trigger Incapsula and extract script paths
	if err := s.makeInitialRequest(ctx); err != nil {
		return false, fmt.Errorf("initial request failed: %w", err)
	}

	// Step 2: Fetch the Reese84 script content
	log.Println("Step 2: Fetching Reese84 script...")
	if err := s.fetchScript(ctx); err != nil {
		return false, fmt.Errorf("failed to fetch script: %w", err)
	}

	// Step 3: Get POW challenge if enabled
	var pow string
	if s.config.PowEnabled {
		log.Println("Step 3: Fetching POW challenge...")
		var err error
		pow, err = s.getPow(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to get POW: %w", err)
		}
		log.Printf("  POW obtained: %s...", pow[:min(30, len(pow))])
	} else {
		log.Println("Step 3: POW disabled, skipping...")
	}

	// Step 4: Generate sensor via Hyper API
	log.Println("Step 4: Generating Reese84 sensor via Hyper API...")
	sensor, err := s.generateSensor(ctx, pow)
	if err != nil {
		return false, fmt.Errorf("failed to generate sensor: %w", err)
	}
	log.Printf("  Sensor generated: %s...", sensor[:min(50, len(sensor))])

	// Step 5: Submit the sensor
	log.Println("Step 5: Submitting sensor...")
	if err := s.submitSensor(ctx, sensor); err != nil {
		return false, fmt.Errorf("failed to submit sensor: %w", err)
	}

	// Step 6: Verify access to protected page
	log.Println("Step 6: Verifying access to protected page...")
	return s.verifyAccess(ctx)
}

// makeInitialRequest makes the first request to the target page.
// This triggers Incapsula protection and allows us to extract the script paths.
func (s *Reese84Solver) makeInitialRequest(ctx context.Context) error {
	// Set headers that match a real Chrome browser
	// Header order is important for TLS fingerprinting!
	// Note: azuretls requires lowercase header order keys
	headers := http.Header{
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
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

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    s.config.TargetURL,
		Header: headers,
	})
	if err != nil {
		return err
	}

	// Read response body
	body := resp.Body

	// Check for Incapsula challenge page
	if !bytes.Contains(body, []byte("Pardon Our Interruption")) {
		return errors.New("Incapsula challenge not detected - site may not be protected or IP may be blocked")
	}

	log.Println("  Incapsula challenge detected!")

	// Extract script path for sensor POST endpoint
	// Pattern: src="/abc123/def456?..."
	pathRegex := regexp.MustCompile(`src\s*=\s*"(/[^/]+/[^?]+)\?.*"`)
	matches := pathRegex.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return errors.New("failed to extract script path from challenge page")
	}
	s.path = matches[1]
	log.Printf("  Script path: %s", s.path)

	// Extract full script path with query params for fetching
	// Pattern: scriptElement.src = "/abc123/def456?d=example.com&..."
	fullPathRegex := regexp.MustCompile(`scriptElement\.src\s*=\s*"(.*?)"`)
	matches = fullPathRegex.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return errors.New("failed to extract full script path from challenge page")
	}
	s.fullPath = matches[1]
	log.Printf("  Full script path: %s", s.fullPath)

	return nil
}

// fetchScript retrieves the Reese84 script content.
func (s *Reese84Solver) fetchScript(ctx context.Context) error {
	// Parse target URL to get the host
	targetURL, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return err
	}

	scriptURL := fmt.Sprintf("%s://%s%s", targetURL.Scheme, targetURL.Host, s.fullPath)

	headers := http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {s.config.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language",
		},
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    scriptURL,
		Header: headers,
	})
	if err != nil {
		return err
	}

	s.script = string(resp.Body)
	log.Printf("  Script fetched: %d bytes", len(s.script))

	return nil
}

// getPow fetches the POW (Proof of Work) challenge from the server.
// This is required by some sites before sensor submission.
func (s *Reese84Solver) getPow(ctx context.Context) (string, error) {
	// Parse target URL to get the host
	targetURL, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return "", err
	}

	// POW endpoint uses the same path as sensor submission
	powURL := fmt.Sprintf("%s://%s%s?d=%s", targetURL.Scheme, targetURL.Host, s.path, targetURL.Host)

	// POW request body is hardcoded
	powBody := `{"f":"gpc"}`

	headers := http.Header{
		"pragma":             {"no-cache"},
		"cache-control":      {"no-cache"},
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {UserAgent},
		"accept":             {"application/json; charset=utf-8"},
		"sec-ch-ua":          {SecChUa},
		"content-type":       {"text/plain; charset=utf-8"},
		"sec-ch-ua-mobile":   {"?0"},
		"origin":             {fmt.Sprintf("%s://%s", targetURL.Scheme, targetURL.Host)},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {s.config.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length", "pragma", "cache-control", "sec-ch-ua-platform",
			"user-agent", "accept", "sec-ch-ua", "content-type", "sec-ch-ua-mobile",
			"origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language", "priority",
		},
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "POST",
		Url:    powURL,
		Body:   powBody,
		Header: headers,
	})
	if err != nil {
		return "", err
	}

	// Response is a JSON string
	var pow string
	if err := json.Unmarshal(resp.Body, &pow); err != nil {
		return "", fmt.Errorf("failed to parse POW response: %w", err)
	}

	return pow, nil
}

// generateSensor calls the Hyper API to generate a Reese84 sensor.
func (s *Reese84Solver) generateSensor(ctx context.Context, pow string) (string, error) {
	// Parse target URL to build script URL
	targetURL, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return "", err
	}

	scriptURL := fmt.Sprintf("%s://%s%s", targetURL.Scheme, targetURL.Host, s.fullPath)

	input := &hyper.ReeseInput{
		UserAgent:      UserAgent,
		AcceptLanguage: s.config.AcceptLanguage,
		IP:             s.ip,
		ScriptUrl:      scriptURL,
		PageUrl:        s.config.TargetURL,
		Pow:            pow,
		Script:         s.script,
	}

	sensor, err := s.hyperAPI.GenerateReese84Sensor(ctx, input)
	if err != nil {
		return "", fmt.Errorf("Hyper API error: %w", err)
	}

	return sensor, nil
}

// submitSensor posts the generated sensor to the Incapsula endpoint.
func (s *Reese84Solver) submitSensor(ctx context.Context, sensor string) error {
	// Parse target URL to get the host
	targetURL, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return err
	}

	// Sensor endpoint: https://{domain}{path}?d={domain}
	sensorURL := fmt.Sprintf("%s://%s%s?d=%s", targetURL.Scheme, targetURL.Host, s.path, targetURL.Host)

	headers := http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {UserAgent},
		"accept":             {"application/json; charset=utf-8"},
		"sec-ch-ua":          {SecChUa},
		"content-type":       {"text/plain; charset=utf-8"},
		"sec-ch-ua-mobile":   {"?0"},
		"origin":             {fmt.Sprintf("%s://%s", targetURL.Scheme, targetURL.Host)},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {s.config.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length", "sec-ch-ua-platform", "user-agent", "accept",
			"sec-ch-ua", "content-type", "sec-ch-ua-mobile", "origin",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie", "priority",
		},
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "POST",
		Url:    sensorURL,
		Body:   sensor,
		Header: headers,
	})
	if err != nil {
		return err
	}

	// Parse response to get the token
	var result struct {
		Token        string `json:"token"`
		CookieDomain string `json:"cookieDomain"`
	}
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		return fmt.Errorf("failed to parse sensor response: %w", err)
	}

	if result.Token == "" {
		return errors.New("no token received in sensor response")
	}

	// Set the reese84 cookie
	cookieURL, _ := url.Parse(s.config.CookieDomain)
	s.session.CookieJar.SetCookies(cookieURL, []*http.Cookie{
		{
			Name:   "reese84",
			Value:  result.Token,
			Domain: result.CookieDomain,
		},
	})

	log.Printf("  Token received and cookie set: %s...", result.Token[:min(30, len(result.Token))])

	return nil
}

// verifyAccess makes a final request to verify we can access the protected page.
func (s *Reese84Solver) verifyAccess(ctx context.Context) (bool, error) {
	headers := http.Header{
		"cache-control":             {"max-age=0"},
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"same-origin"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-dest":            {"document"},
		"referer":                   {s.config.Referer},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {s.config.AcceptLanguage},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
			"sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding",
			"accept-language", "cookie", "priority",
		},
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    s.config.TargetURL,
		Header: headers,
	})
	if err != nil {
		return false, err
	}

	// Check if we're still seeing the challenge page
	if bytes.Contains(resp.Body, []byte("Pardon Our Interruption")) {
		log.Printf("Failed! Still seeing challenge page (HTTP %d)", resp.StatusCode)
		return false, nil
	}

	success := resp.StatusCode == 200
	if success {
		log.Printf("Success! Access granted (HTTP %d)", resp.StatusCode)
	} else {
		log.Printf("Failed! Access denied (HTTP %d)", resp.StatusCode)
	}

	return success, nil
}

// Close releases resources associated with the solver.
func (s *Reese84Solver) Close() {
	if s.session != nil {
		s.session.Close()
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getPublicIP retrieves the client's public IP address.
// This is required for generating valid Reese84 sensors.
func getPublicIP(ctx context.Context, session *azuretls.Session) (string, error) {
	resp, err := session.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(resp.Body)), nil
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	// Load configuration
	config := DefaultConfig()

	// Configure for your target site
	config.TargetURL = "https://digital.example.com/book"
	config.Referer = "https://digital.example.com/"
	config.CookieDomain = "https://digital.example.com/"

	// Enable POW if required by the target site
	config.PowEnabled = false

	// Validate API key
	if config.APIKey == "" {
		log.Fatal("HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co")
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create solver
	solver, err := NewReese84Solver(ctx, config)
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
		fmt.Println("\n✅ Incapsula Reese84 bypass successful!")
		fmt.Println("You can now make authenticated requests using the same session.")
	} else {
		fmt.Println("\n❌ Incapsula Reese84 bypass failed.")
		fmt.Println("The IP may be blocked or additional challenges are required.")
		os.Exit(1)
	}
}
