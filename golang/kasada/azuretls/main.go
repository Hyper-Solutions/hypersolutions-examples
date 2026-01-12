// Package main provides a complete example of bypassing Kasada protection
// using the Hyper Solutions SDK with the Noooste/azuretls-client.
//
// This example demonstrates:
//   - Setting up an AzureTLS client with proper browser fingerprinting
//   - Detecting Kasada protection (429 on page vs /fp endpoint)
//   - Fetching and solving ips.js challenges
//   - Generating payload data (CT) and POW tokens (CD)
//   - Handling BotID verification when required
//   - The complete flow from initial request to successful bypass
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
	"strconv"
	"strings"
	"time"

	"github.com/Noooste/azuretls-client"
	http "github.com/Noooste/fhttp"

	hyper "github.com/Hyper-Solutions/hyper-sdk-go/v2"
	"github.com/Hyper-Solutions/hyper-sdk-go/v2/kasada"
)

// =============================================================================
// CONFIGURATION
// =============================================================================

// Config holds all configuration for the Kasada bypass example.
// Modify these values according to your target site and environment.
type Config struct {
	// APIKey is your Hyper Solutions API key.
	// Get yours at: https://hypersolutions.co
	APIKey string

	// PageURL is the protected page you want to access.
	PageURL string

	// AcceptLanguage is the browser's accept-language header.
	// Should match your target region/language.
	AcceptLanguage string

	// ProxyURL is an optional HTTP/HTTPS/SOCKS5 proxy.
	// Leave empty to connect directly.
	ProxyURL string

	// Timeout is the HTTP request timeout duration.
	Timeout time.Duration

	// BotIDEnabled enables BotID/Vercel protection solving.
	// Set to true if the site uses BotID verification.
	BotIDEnabled bool
}

// DefaultConfig returns a sensible default configuration.
// You MUST replace the APIKey and PageURL with your own values.
func DefaultConfig() *Config {
	return &Config{
		APIKey:         os.Getenv("HYPER_API_KEY"), // Set via environment variable
		PageURL:        "https://example.com/protected-page",
		AcceptLanguage: "en-US,en;q=0.9",
		ProxyURL:       os.Getenv("HTTP_PROXY"), // Optional: set via environment variable
		Timeout:        30 * time.Second,
		BotIDEnabled:   false,
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

	// KasadaVersion is the Kasada SDK version.
	KasadaVersion = "j-1.1.29140"

	// Fixed Kasada paths
	KasadaBasePath = "/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3"
)

// =============================================================================
// KASADA SOLVER
// =============================================================================

// KasadaSolver handles the complete Kasada bypass flow.
type KasadaSolver struct {
	config   *Config
	session  *azuretls.Session
	hyperAPI *hyper.Session

	// Derived from PageURL
	domain  string
	baseURL string

	// Internal state
	ip        string
	ipsScript string
	ipsLink   string

	// Headers from /tl response
	tlHeaders struct {
		Ct string
		St int
	}

	// Headers from /mfc response
	mfcHeaders struct {
		Fc string
		H  string
	}
}

// NewKasadaSolver creates a new solver instance.
func NewKasadaSolver(ctx context.Context, config *Config) (*KasadaSolver, error) {
	if config.APIKey == "" {
		return nil, errors.New("API key is required - get yours at https://hypersolutions.co")
	}
	if config.PageURL == "" {
		return nil, errors.New("page URL is required")
	}

	// Parse domain from PageURL
	parsedURL, err := url.Parse(config.PageURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse page URL: %w", err)
	}

	// Create AzureTLS session with context
	session := azuretls.NewSessionWithContext(ctx)

	// Set timeout
	session.SetTimeout(config.Timeout)

	// Pin manager doesn't work with HTTP debuggers, recommended to enable in production
	session.InsecureSkipVerify = true

	// Use Chrome browser fingerprint - this automatically sets up TLS and HTTP/2 fingerprints
	session.GetClientHelloSpec = azuretls.GetLastChromeVersion

	// Configure to not follow redirects - we need to detect Kasada challenge redirects
	session.MaxRedirects = 0

	// Add proxy if configured
	if config.ProxyURL != "" {
		if err := session.SetProxy(config.ProxyURL); err != nil {
			return nil, fmt.Errorf("failed to set proxy: %w", err)
		}
	}

	hyperAPI := hyper.NewSession(config.APIKey)

	ip, err := getPublicIP(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP: %w", err)
	}
	log.Printf("Public IP: %s", ip)

	return &KasadaSolver{
		config:   config,
		session:  session,
		hyperAPI: hyperAPI,
		domain:   parsedURL.Host,
		baseURL:  fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host),
		ip:       ip,
	}, nil
}

// Solve attempts to bypass Kasada protection and access the target page.
// Returns true if successful, false if blocked.
func (s *KasadaSolver) Solve(ctx context.Context) (bool, error) {
	log.Println("Step 1: Making initial request to detect Kasada protection...")

	// Step 1: Fetch the page and check for 429
	statusCode, pageBody, err := s.fetchPage(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to fetch page: %w", err)
	}

	if statusCode == 429 {
		// Flow 1: 429 on page URL - solve and reload
		log.Println("Step 2: Detected 429 on page, solving Kasada challenge...")
		if err := s.solveFromBlockPage(ctx, pageBody); err != nil {
			return false, fmt.Errorf("failed to solve from block page: %w", err)
		}

		// Reload page
		log.Println("Step 3: Reloading page after solving...")
		statusCode, _, err = s.fetchPage(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to reload page: %w", err)
		}

		if statusCode != 200 {
			log.Printf("Failed! Page still returning %d after solve", statusCode)
			return false, nil
		}

		log.Println("  Page loaded successfully!")
	} else {
		// Flow 2: No 429 on page - solve via /fp endpoint
		log.Println("Step 2: No 429 on page, solving via /fp endpoint...")
		if err := s.solveFromFpEndpoint(ctx); err != nil {
			return false, fmt.Errorf("failed to solve from /fp: %w", err)
		}
	}

	// Step 4: Handle BotID if enabled
	if s.config.BotIDEnabled {
		log.Println("Step 4: Solving BotID challenge...")
		if err := s.solveBotID(ctx); err != nil {
			return false, fmt.Errorf("failed to solve BotID: %w", err)
		}
	} else {
		log.Println("Step 4: BotID disabled, skipping...")
	}

	// Step 5: Generate POW (x-kpsdk-cd) for demonstration
	log.Println("Step 5: Generating POW (x-kpsdk-cd) for API requests...")
	if err := s.generatePow(ctx); err != nil {
		return false, fmt.Errorf("failed to generate POW: %w", err)
	}

	log.Println("\n✅ Kasada bypass successful!")
	return true, nil
}

// fetchPage makes a GET request to the page URL.
func (s *KasadaSolver) fetchPage(ctx context.Context) (int, []byte, error) {
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
		Url:    s.config.PageURL,
		Header: headers,
	})
	if err != nil {
		return 0, nil, err
	}

	log.Printf("  Page response: %d", resp.StatusCode)

	return resp.StatusCode, resp.Body, nil
}

// solveFromBlockPage handles the flow when page returns 429.
func (s *KasadaSolver) solveFromBlockPage(ctx context.Context, blockPageBody []byte) error {
	// Extract ips.js URL from block page
	ipsPath, err := kasada.ParseScriptPath(bytes.NewReader(blockPageBody))
	if err != nil {
		return fmt.Errorf("failed to parse script path: %w", err)
	}

	s.ipsLink = s.baseURL + ipsPath
	log.Printf("  IPS script URL: %s", s.ipsLink)

	// Fetch ips.js script
	if err := s.fetchIpsScript(ctx); err != nil {
		return err
	}

	// Generate and submit payload
	return s.solveChallenge(ctx)
}

// solveFromFpEndpoint handles the flow when page doesn't return 429.
func (s *KasadaSolver) solveFromFpEndpoint(ctx context.Context) error {
	// Request /fp endpoint to trigger 429
	fpURL := fmt.Sprintf("%s%s/fp?x-kpsdk-v=%s", s.baseURL, KasadaBasePath, KasadaVersion)

	headers := http.Header{
		"sec-ch-ua":                 {SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {SecChUaPlatform},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"same-origin"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-dest":            {"iframe"},
		"referer":                   {s.config.PageURL},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {s.config.AcceptLanguage},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
			"sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding",
			"accept-language", "priority",
		},
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    fpURL,
		Header: headers,
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != 429 {
		return fmt.Errorf("/fp returned unexpected status code: %d", resp.StatusCode)
	}

	log.Println("  /fp returned 429, extracting script...")

	// Extract ips.js URL
	ipsPath, err := kasada.ParseScriptPath(bytes.NewReader(resp.Body))
	if err != nil {
		return fmt.Errorf("failed to parse script path: %w", err)
	}

	s.ipsLink = s.baseURL + ipsPath
	log.Printf("  IPS script URL: %s", s.ipsLink)

	// Fetch ips.js script
	if err := s.fetchIpsScript(ctx); err != nil {
		return err
	}

	// Generate and submit payload
	return s.solveChallenge(ctx)
}

// fetchIpsScript retrieves the ips.js script content.
func (s *KasadaSolver) fetchIpsScript(ctx context.Context) error {
	headers := http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {s.config.PageURL},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1"},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile",
			"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
			"referer", "accept-encoding", "accept-language", "cookie", "priority",
		},
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    s.ipsLink,
		Header: headers,
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("ips.js request returned %d", resp.StatusCode)
	}

	s.ipsScript = string(resp.Body)
	log.Printf("  IPS script fetched: %d bytes", len(s.ipsScript))

	return nil
}

// solveChallenge generates payload and submits to /tl endpoint.
func (s *KasadaSolver) solveChallenge(ctx context.Context) error {
	log.Println("  Generating Kasada payload via Hyper API...")

	// Generate payload
	payload, headers, err := s.hyperAPI.GenerateKasadaPayload(ctx, &hyper.KasadaPayloadInput{
		UserAgent:      UserAgent,
		IpsLink:        s.ipsLink,
		Script:         s.ipsScript,
		AcceptLanguage: s.config.AcceptLanguage,
		IP:             s.ip,
	})
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}

	log.Println("  Submitting payload to /tl...")

	// Submit to /tl
	tlURL := fmt.Sprintf("%s%s/tl", s.baseURL, KasadaBasePath)

	reqHeaders := http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"user-agent":         {UserAgent},
		"content-type":       {"application/octet-stream"},
		"accept":             {"*/*"},
		"origin":             {s.baseURL},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {s.config.PageURL},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length", "x-kpsdk-ct", "x-kpsdk-dt", "sec-ch-ua-platform",
			"sec-ch-ua", "x-kpsdk-im", "sec-ch-ua-mobile", "x-kpsdk-v",
			"user-agent", "content-type", "accept", "origin",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "cookie", "priority",
		},
	}

	// Set Kasada headers from payload generation
	if headers.XKpsdkCt != "" {
		reqHeaders.Set("x-kpsdk-ct", headers.XKpsdkCt)
	}
	if headers.XKpsdkDt != "" {
		reqHeaders.Set("x-kpsdk-dt", headers.XKpsdkDt)
	}
	if headers.XKpsdkV != "" {
		reqHeaders.Set("x-kpsdk-v", headers.XKpsdkV)
	}
	if headers.XKpsdkR != "" {
		reqHeaders.Set("x-kpsdk-r", headers.XKpsdkR)
	}
	if headers.XKpsdkDv != "" {
		reqHeaders.Set("x-kpsdk-dv", headers.XKpsdkDv)
	}
	if headers.XKpsdkH != "" {
		reqHeaders.Set("x-kpsdk-h", headers.XKpsdkH)
	}
	if headers.XKpsdkFc != "" {
		reqHeaders.Set("x-kpsdk-fc", headers.XKpsdkFc)
	}
	if headers.XKpsdkIm != "" {
		reqHeaders.Set("x-kpsdk-im", headers.XKpsdkIm)
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "POST",
		Url:    tlURL,
		Body:   payload,
		Header: reqHeaders,
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("/tl returned %d", resp.StatusCode)
	}

	// Check for reload:true
	var tlResponse struct {
		Reload bool `json:"reload"`
	}
	if err := json.Unmarshal(resp.Body, &tlResponse); err != nil {
		return fmt.Errorf("failed to parse /tl response: %w", err)
	}

	if !tlResponse.Reload {
		return errors.New("/tl did not return reload:true")
	}

	log.Println("  /tl returned reload:true - challenge solved!")

	// Store headers for POW generation
	s.tlHeaders.Ct = resp.Header.Get("x-kpsdk-ct")
	stStr := resp.Header.Get("x-kpsdk-st")
	if stStr != "" {
		s.tlHeaders.St, _ = strconv.Atoi(stStr)
	}

	// Log response headers
	log.Println("\n  Response headers from /tl:")
	log.Printf("    x-kpsdk-ct: %s", s.tlHeaders.Ct)
	log.Printf("    x-kpsdk-st: %d", s.tlHeaders.St)

	return nil
}

// solveBotID handles the BotID/Vercel verification.
func (s *KasadaSolver) solveBotID(ctx context.Context) error {
	// Fetch BotID script
	botIDURL := fmt.Sprintf("%s%s/a-4-a/c.js?i=0&v=3&h=%s", s.baseURL, KasadaBasePath, s.domain)

	headers := http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"user-agent":         {UserAgent},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {s.config.PageURL},
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
		Url:    botIDURL,
		Header: headers,
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("BotID script request returned %d", resp.StatusCode)
	}

	log.Printf("  BotID script fetched: %d bytes", len(resp.Body))

	// Generate BotID header
	isHumanHeader, err := s.hyperAPI.GenerateBotIDHeader(ctx, &hyper.BotIDHeaderInput{
		Script:         string(resp.Body),
		UserAgent:      UserAgent,
		IP:             s.ip,
		AcceptLanguage: s.config.AcceptLanguage,
	})
	if err != nil {
		return fmt.Errorf("failed to generate BotID header: %w", err)
	}

	log.Printf("  x-is-human header generated: %s...", isHumanHeader[:min(50, len(isHumanHeader))])

	return nil
}

// generatePow generates the x-kpsdk-cd header for protected API requests.
func (s *KasadaSolver) generatePow(ctx context.Context) error {
	// First, make /mfc request to get fc and h headers
	log.Println("  Making /mfc request...")

	mfcURL := fmt.Sprintf("%s%s/mfc", s.baseURL, KasadaBasePath)

	headers := http.Header{
		"sec-ch-ua-platform": {SecChUaPlatform},
		"x-kpsdk-h":          {"01"},
		"sec-ch-ua":          {SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"x-kpsdk-v":          {KasadaVersion},
		"user-agent":         {UserAgent},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {s.config.PageURL},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {s.config.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform", "x-kpsdk-h", "sec-ch-ua", "sec-ch-ua-mobile",
			"x-kpsdk-v", "user-agent", "accept", "sec-fetch-site",
			"sec-fetch-mode", "sec-fetch-dest", "referer", "accept-encoding",
			"accept-language", "cookie", "priority",
		},
	}

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    mfcURL,
		Header: headers,
	})
	if err != nil {
		return err
	}

	s.mfcHeaders.Fc = resp.Header.Get("x-kpsdk-fc")
	s.mfcHeaders.H = resp.Header.Get("x-kpsdk-h")

	log.Printf("  /mfc headers - x-kpsdk-fc: %s..., x-kpsdk-h: %s",
		s.mfcHeaders.Fc[:min(30, len(s.mfcHeaders.Fc))], s.mfcHeaders.H)

	// Generate POW
	log.Println("  Generating x-kpsdk-cd via Hyper API...")

	cd, err := s.hyperAPI.GenerateKasadaPow(ctx, &hyper.KasadaPowInput{
		St:     s.tlHeaders.St,
		Ct:     s.tlHeaders.Ct,
		Fc:     s.mfcHeaders.Fc,
		Domain: s.domain,
		// Script field is deprecated, leave empty
	})
	if err != nil {
		return fmt.Errorf("failed to generate POW: %w", err)
	}

	log.Println("\n  ✅ POW generated successfully!")
	log.Println("\n  Headers for protected API requests:")
	log.Printf("    x-kpsdk-ct: %s", s.tlHeaders.Ct)
	log.Printf("    x-kpsdk-cd: %s", cd)
	log.Printf("    x-kpsdk-h:  %s", s.mfcHeaders.H)
	log.Printf("    x-kpsdk-v:  %s", KasadaVersion)

	return nil
}

// Close releases resources associated with the solver.
func (s *KasadaSolver) Close() {
	if s.session != nil {
		s.session.Close()
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// getPublicIP retrieves the client's public IP address.
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
	config.PageURL = "https://www.example.com/"

	// Enable BotID if the site uses Vercel BotID protection
	config.BotIDEnabled = false

	// Validate API key
	if config.APIKey == "" {
		log.Fatal("HYPER_API_KEY environment variable not set. Get your API key at https://hypersolutions.co")
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create solver
	solver, err := NewKasadaSolver(ctx, config)
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
		fmt.Println("\nYou can now make authenticated requests using the same session.")
		fmt.Println("Remember to include x-kpsdk-ct, x-kpsdk-cd, x-kpsdk-h, and x-kpsdk-v headers on protected API requests.")
	} else {
		fmt.Println("\n❌ Kasada bypass failed.")
		fmt.Println("The IP may be blocked or additional challenges are required.")
		os.Exit(1)
	}
}
