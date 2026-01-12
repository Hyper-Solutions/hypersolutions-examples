// Package main provides a complete example of bypassing Akamai Bot Manager protection
// using the Hyper Solutions SDK with the Noooste/azuretls-client.
//
// This example demonstrates:
//   - Setting up an AzureTLS client with proper browser fingerprinting
//   - Detecting and solving SBSD (State-Based Scraping Detection) challenges
//   - Handling SBSD with and without the "t" parameter
//   - Generating and submitting sensor data via the Hyper API
//   - Cookie validation and the complete bypass flow
//
// For more information, visit: https://docs.hypersolutions.co
// Join our Discord community: https://discord.gg/akamai
package main

import (
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
	"github.com/Hyper-Solutions/hyper-sdk-go/v2/akamai"
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
// SBSD DETECTION
// =============================================================================

// SbsdInfo holds extracted SBSD information from the page.
type SbsdInfo struct {
	Path string // Script path (e.g., /abc/def)
	Uuid string // UUID/version parameter
	T    string // Optional "t" parameter (indicates hardblock if present)
}

// sbsdRegex extracts SBSD script information from page HTML.
var sbsdRegex = regexp.MustCompile(`(?i)([a-z\d/\-_\.]+)\?v=(.*?)(?:&.*?t=(.*?))?["']`)

// parseSbsdInfo attempts to extract SBSD information from page HTML.
// Returns nil if SBSD is not detected.
func parseSbsdInfo(html string) *SbsdInfo {
	matches := sbsdRegex.FindStringSubmatch(html)
	if len(matches) < 3 {
		return nil
	}

	info := &SbsdInfo{
		Path: matches[1],
		Uuid: matches[2],
	}

	if len(matches) >= 4 {
		info.T = matches[3]
	}

	return info
}

// IsHardblock returns true if SBSD is in hardblock mode (t parameter present).
func (s *SbsdInfo) IsHardblock() bool {
	return s.T != ""
}

// ScriptURL returns the full URL to fetch the SBSD script.
func (s *SbsdInfo) ScriptURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	scriptURL := fmt.Sprintf("%s://%s%s?v=%s", u.Scheme, u.Host, s.Path, s.Uuid)
	if s.T != "" {
		scriptURL += "&t=" + s.T
	}

	return scriptURL, nil
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
// AKAMAI SOLVER
// =============================================================================

// AkamaiSolver handles the complete Akamai bypass flow.
type AkamaiSolver struct {
	config   *Config
	session  *azuretls.Session
	hyperAPI *hyper.Session

	// Internal state
	ip             string
	pageHTML       string
	sbsdInfo       *SbsdInfo
	sbsdScript     string
	sensorScript   string
	sensorEndpoint string
	sensorContext  string
}

// NewAkamaiSolver creates a new solver instance.
func NewAkamaiSolver(ctx context.Context, config *Config) (*AkamaiSolver, error) {
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

	// Configure to not follow redirects - we need to detect Akamai challenge redirects
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

	return &AkamaiSolver{
		config:   config,
		session:  session,
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

	s.pageHTML = string(resp.Body)

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
		// Hardblock mode: post once, then reload page
		log.Println("  Hardblock mode: posting single SBSD payload...")
		if err := s.postSbsd(ctx, 0); err != nil {
			return err
		}

		// Reload the page
		log.Println("  Reloading page after SBSD...")
		if err := s.fetchPage(ctx); err != nil {
			return err
		}
	} else {
		// Non-hardblock mode: post twice with index 0 and 1
		log.Println("  Non-hardblock mode: posting two SBSD payloads...")
		if err := s.postSbsd(ctx, 0); err != nil {
			return err
		}
		if err := s.postSbsd(ctx, 1); err != nil {
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

	headers := http.Header{
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

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    scriptURL,
		Header: headers,
	})
	if err != nil {
		return err
	}

	s.sbsdScript = string(resp.Body)
	log.Printf("  SBSD script fetched: %d bytes", len(s.sbsdScript))

	return nil
}

// postSbsd submits an SBSD payload.
func (s *AkamaiSolver) postSbsd(ctx context.Context, index int) error {
	// Get the O cookie (bm_so or sbsd_o)
	oCookie := s.getCookie("bm_so")
	if oCookie == "" {
		oCookie = s.getCookie("sbsd_o")
	}

	input := &hyper.SbsdInput{
		Index:          index,
		UserAgent:      UserAgent,
		Uuid:           s.sbsdInfo.Uuid,
		PageUrl:        s.config.TargetURL,
		OCookie:        oCookie,
		Script:         s.sbsdScript,
		AcceptLanguage: s.config.AcceptLanguage,
		IP:             s.ip,
	}

	payload, err := s.hyperAPI.GenerateSbsdData(ctx, input)
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}

	postURL, err := s.sbsdInfo.PostURL(s.config.TargetURL)
	if err != nil {
		return err
	}

	// Wrap payload in JSON body
	bodyJSON, err := json.Marshal(map[string]string{"body": payload})
	if err != nil {
		return err
	}

	targetURL, _ := url.Parse(s.config.TargetURL)

	headers := http.Header{
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

	_, err = s.session.Do(&azuretls.Request{
		Method: "POST",
		Url:    postURL,
		Body:   string(bodyJSON),
		Header: headers,
	})
	if err != nil {
		return err
	}

	log.Printf("  SBSD payload %d submitted", index)

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
	headers := http.Header{
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

	resp, err := s.session.Do(&azuretls.Request{
		Method: "GET",
		Url:    s.sensorEndpoint,
		Header: headers,
	})
	if err != nil {
		return err
	}

	s.sensorScript = string(resp.Body)
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

	sensorData, sensorContext, err := s.hyperAPI.GenerateSensorData(ctx, input)
	if err != nil {
		return fmt.Errorf("Hyper API error: %w", err)
	}

	// Store context for subsequent requests
	s.sensorContext = sensorContext

	// Wrap sensor data in JSON
	bodyJSON, err := json.Marshal(map[string]string{"sensor_data": sensorData})
	if err != nil {
		return err
	}

	targetURL, _ := url.Parse(s.config.TargetURL)

	headers := http.Header{
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

	_, err = s.session.Do(&azuretls.Request{
		Method: "POST",
		Url:    s.sensorEndpoint,
		Body:   string(bodyJSON),
		Header: headers,
	})
	if err != nil {
		return err
	}

	return nil
}

// getCookie retrieves a cookie value by name from the session's cookie jar.
func (s *AkamaiSolver) getCookie(name string) string {
	u, err := url.Parse(s.config.TargetURL)
	if err != nil {
		return ""
	}

	cookies := s.session.CookieJar.Cookies(u)
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}

	return ""
}

// Close releases resources associated with the solver.
func (s *AkamaiSolver) Close() {
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
	config.TargetURL = "https://www.delta.com/us/en"
	config.Referer = "https://www.delta.com/us/en"
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
		fmt.Println("You can now make authenticated requests using the same session.")
	} else {
		fmt.Println("\n❌ Akamai bypass failed.")
		fmt.Println("The IP may be blocked or additional challenges are required.")
		os.Exit(1)
	}
}
