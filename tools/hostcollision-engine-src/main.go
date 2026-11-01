package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	titlePattern              = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	tagPattern                = regexp.MustCompile(`(?s)<[^>]+>`)
	tagNamePattern            = regexp.MustCompile(`(?is)<\s*(/?)\s*([a-z][a-z0-9:_-]*)\b`)
	spacePattern              = regexp.MustCompile(`\s+`)
	tokenPattern              = regexp.MustCompile(`[[:alnum:]_\-]{2,}`)
	volatileAttributePattern  = regexp.MustCompile(`(?i)((?:value|nonce|token|csrf|session|request[_-]?id|trace[_-]?id)\s*=\s*["'])[^"']+(["'])`)
	volatileAssignmentPattern = regexp.MustCompile(`(?i)((?:csrf|nonce|token|session|request[_-]?id|trace[_-]?id)["'\s:=]+)[a-z0-9_./+=\-]{6,}`)
	volatileUUIDPattern       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	volatileHexPattern        = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	volatileNumberPattern     = regexp.MustCompile(`\b[0-9]{6,}\b`)
	parkingPattern            = regexp.MustCompile(`(?i)(domain parking|domain is parked|buy this domain|this domain is for sale|serwerach nazwa\.pl)`)
)

type endpoint struct {
	Scheme  string   `json:"scheme"`
	IP      string   `json:"ip"`
	Port    int      `json:"port"`
	Sources []string `json:"sources,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

func (e endpoint) key() string {
	return fmt.Sprintf("%s://%s:%d", e.Scheme, e.IP, e.Port)
}

func (e endpoint) address() string {
	return net.JoinHostPort(e.IP, strconv.Itoa(e.Port))
}

type input struct {
	Endpoints           []endpoint          `json:"endpoints"`
	Domains             []string            `json:"domains"`
	BaseDomain          string              `json:"base_domain,omitempty"`
	Paths               map[string][]string `json:"paths,omitempty"`
	Concurrency         int                 `json:"concurrency"`
	EndpointConcurrency int                 `json:"endpoint_concurrency"`
	HostConcurrency     int                 `json:"host_concurrency"`
	ConnectTimeoutMS    int                 `json:"connect_timeout_ms"`
	RequestTimeoutMS    int                 `json:"request_timeout_ms"`
	MaxBodyBytes        int64               `json:"max_body_bytes"`
	MinBodyLength       int                 `json:"min_body_length"`
	AcceptRedirect      bool                `json:"accept_redirect"`
	PathLimit           int                 `json:"path_limit"`
	Retries             int                 `json:"retries"`
}

type page struct {
	StatusCode        int
	ContentType       string
	Body              []byte
	BodyLength        int
	Title             string
	Location          string
	Path              string
	HostHeader        string
	NormalizedHash    string
	NormalizedTitle   string
	Simhash           uint64
	StructureHash     string
	StabilityHash     string
	StabilitySimhash  uint64
	StabilityLength   int
	StabilityLocation string
	Truncated         bool
}

type result struct {
	URL               string   `json:"url"`
	Domain            string   `json:"domain"`
	IP                string   `json:"ip"`
	Port              int      `json:"port"`
	Scheme            string   `json:"scheme"`
	Path              string   `json:"path"`
	HostHeader        string   `json:"host_header"`
	SNI               string   `json:"sni"`
	Title             string   `json:"title"`
	StatusCode        int      `json:"status_code"`
	BodyLength        int      `json:"body_length"`
	RedirectLocation  string   `json:"redirect_location"`
	Confidence        string   `json:"confidence"`
	Quality           string   `json:"quality"`
	VerificationState string   `json:"verification_state"`
	ResponseSignature string   `json:"response_signature"`
	EndpointSources   []string `json:"endpoint_sources,omitempty"`
	BaselineCount     int      `json:"baseline_count"`
	StabilityChecks   int      `json:"stability_checks"`
	BodyTruncated     bool     `json:"body_truncated"`
}

type event struct {
	Type               string  `json:"type"`
	Result             *result `json:"result,omitempty"`
	EndpointKey        string  `json:"endpoint_key,omitempty"`
	CompletedEndpoints int64   `json:"completed_endpoints,omitempty"`
	TotalEndpoints     int     `json:"total_endpoints,omitempty"`
	RequestCount       int64   `json:"request_count,omitempty"`
	ResponseCount      int64   `json:"response_count,omitempty"`
	ErrorCount         int64   `json:"error_count,omitempty"`
	ResultCount        int64   `json:"result_count,omitempty"`
	TotalRequestCount  int64   `json:"total_request_count,omitempty"`
	TotalResponseCount int64   `json:"total_response_count,omitempty"`
	TotalErrorCount    int64   `json:"total_error_count,omitempty"`
	TotalResultCount   int64   `json:"total_result_count,omitempty"`
	Skipped            bool    `json:"skipped,omitempty"`
	Error              string  `json:"error,omitempty"`
}

type emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (e *emitter) emit(value event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.enc.Encode(value)
}

type scanner struct {
	config     input
	emitter    *emitter
	requestSem chan struct{}
	requests   atomic.Int64
	responses  atomic.Int64
	errors     atomic.Int64
	results    atomic.Int64
	completed  atomic.Int64
}

type scanStats struct {
	requests  atomic.Int64
	responses atomic.Int64
	errors    atomic.Int64
	results   atomic.Int64
}

func defaults(config *input) {
	if config.Concurrency <= 0 {
		config.Concurrency = 128
	}
	if config.EndpointConcurrency <= 0 {
		config.EndpointConcurrency = 8
	}
	if config.HostConcurrency <= 0 {
		config.HostConcurrency = 16
	}
	if config.ConnectTimeoutMS <= 0 {
		config.ConnectTimeoutMS = 1800
	}
	if config.RequestTimeoutMS <= 0 {
		config.RequestTimeoutMS = 6000
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = 128 * 1024
	}
	if config.MinBodyLength <= 0 {
		config.MinBodyLength = 300
	}
	if config.PathLimit <= 0 {
		config.PathLimit = 3
	}
	if config.Retries < 0 {
		config.Retries = 0
	}
}

func normalizeDomain(value string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".*")
}

func normalizePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	if parsed, err := url.Parse(value); err == nil && parsed.IsAbs() {
		value = parsed.EscapedPath()
		if parsed.RawQuery != "" {
			value += "?" + parsed.RawQuery
		}
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return value
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeDomain(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}

func (s *scanner) acquire(ctx context.Context) error {
	select {
	case s.requestSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *scanner) release() {
	<-s.requestSem
}

func (s *scanner) tcpReady(ctx context.Context, ep endpoint) bool {
	timeouts := []time.Duration{
		time.Duration(s.config.ConnectTimeoutMS) * time.Millisecond,
		time.Duration(s.config.ConnectTimeoutMS*2) * time.Millisecond,
	}
	for _, timeout := range timeouts {
		if err := s.acquire(ctx); err != nil {
			return false
		}
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", ep.address())
		s.release()
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

func (s *scanner) transport(ep endpoint, serverName string) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   time.Duration(s.config.ConnectTimeoutMS) * time.Millisecond,
		KeepAlive: 20 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          s.config.Concurrency,
		MaxIdleConnsPerHost:   s.config.HostConcurrency,
		IdleConnTimeout:       20 * time.Second,
		TLSHandshakeTimeout:   time.Duration(s.config.ConnectTimeoutMS*2) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(s.config.RequestTimeoutMS) * time.Millisecond,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, ep.address())
		},
	}
	if ep.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // The target IP rarely matches the candidate Host certificate.
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS10,
		}
	}
	return transport
}

func extractTitle(body []byte) string {
	match := titlePattern.FindSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	value := tagPattern.ReplaceAll(match[1], nil)
	return strings.TrimSpace(spacePattern.ReplaceAllString(string(value), " "))
}

func normalizeBody(body []byte, host string) []byte {
	value := bytes.ToLower(body)
	host = strings.ToLower(host)
	if host != "" {
		value = bytes.ReplaceAll(value, []byte(host), []byte("{host}"))
	}
	return bytes.TrimSpace(value)
}

func normalizeVolatileBody(body []byte, host string) []byte {
	value := normalizeBody(body, host)
	value = volatileAttributePattern.ReplaceAll(value, []byte(`${1}{volatile}${2}`))
	value = volatileAssignmentPattern.ReplaceAll(value, []byte(`${1}{volatile}`))
	value = volatileUUIDPattern.ReplaceAll(value, []byte(`{uuid}`))
	value = volatileHexPattern.ReplaceAll(value, []byte(`{hex}`))
	value = volatileNumberPattern.ReplaceAll(value, []byte(`{number}`))
	return bytes.TrimSpace(spacePattern.ReplaceAll(value, []byte(" ")))
}

func normalizeVolatileText(value, host string) string {
	return string(normalizeVolatileBody([]byte(value), host))
}

func makeSimhash(body []byte) uint64 {
	if len(body) > 64*1024 {
		body = body[:64*1024]
	}
	tokens := tokenPattern.FindAll(bytes.ToLower(body), -1)
	if len(tokens) == 0 {
		return 0
	}
	weights := [64]int{}
	for _, token := range tokens {
		hasher := fnv.New64a()
		_, _ = hasher.Write(token)
		value := hasher.Sum64()
		for bit := 0; bit < 64; bit++ {
			if value&(uint64(1)<<bit) != 0 {
				weights[bit]++
			} else {
				weights[bit]--
			}
		}
	}
	var output uint64
	for bit, weight := range weights {
		if weight >= 0 {
			output |= uint64(1) << bit
		}
	}
	return output
}

func makeStructureHash(body []byte) string {
	matches := tagNamePattern.FindAllSubmatch(bytes.ToLower(body), -1)
	if len(matches) == 0 {
		return ""
	}
	var structure bytes.Buffer
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		if len(match[1]) > 0 {
			structure.WriteByte('/')
		}
		structure.Write(match[2])
		structure.WriteByte('>')
	}
	if structure.Len() == 0 {
		return ""
	}
	digest := sha256.Sum256(structure.Bytes())
	return hex.EncodeToString(digest[:])
}

func newPage(resp *http.Response, body []byte, hostHeader, path string, truncated bool) page {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	host := strings.Split(hostHeader, ":")[0]
	normalized := normalizeBody(body, host)
	stabilityNormalized := normalizeVolatileBody(body, host)
	digest := sha256.Sum256(normalized)
	stabilityDigest := sha256.Sum256(stabilityNormalized)
	title := extractTitle(body)
	normalizedTitle := strings.ToLower(title)
	normalizedTitle = strings.ReplaceAll(
		normalizedTitle, strings.ToLower(strings.Split(hostHeader, ":")[0]), "{host}")
	normalizedTitle = spacePattern.ReplaceAllString(normalizedTitle, " ")
	normalizedTitle = normalizeVolatileText(normalizedTitle, "")
	return page{
		StatusCode:        resp.StatusCode,
		ContentType:       contentType,
		Body:              body,
		BodyLength:        len(body),
		Title:             title,
		Location:          resp.Header.Get("Location"),
		Path:              path,
		HostHeader:        hostHeader,
		NormalizedHash:    hex.EncodeToString(digest[:]),
		NormalizedTitle:   normalizedTitle,
		Simhash:           makeSimhash(normalized),
		StructureHash:     makeStructureHash(body),
		StabilityHash:     hex.EncodeToString(stabilityDigest[:]),
		StabilitySimhash:  makeSimhash(stabilityNormalized),
		StabilityLength:   len(stabilityNormalized),
		StabilityLocation: normalizeVolatileText(resp.Header.Get("Location"), host),
		Truncated:         truncated,
	}
}

func (s *scanner) fetch(
	ctx context.Context,
	ep endpoint,
	domain, hostHeader, path string,
	transport *http.Transport,
	stats *scanStats,
) (*page, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	s.requests.Add(1)
	stats.requests.Add(1)

	requestURL := fmt.Sprintf("%s://%s%s", ep.Scheme, ep.address(), normalizePath(path))
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(s.config.RequestTimeoutMS)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ARL-HostCollision/2.0)")
	req.Header.Set("Accept", "text/html,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(s.config.RequestTimeoutMS) * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.config.MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	truncated := int64(len(body)) > s.config.MaxBodyBytes
	if truncated {
		body = body[:s.config.MaxBodyBytes]
	}
	value := newPage(resp, body, hostHeader, normalizePath(path), truncated)
	s.responses.Add(1)
	stats.responses.Add(1)
	return &value, nil
}

func hammingDistance(left, right uint64) int {
	value := left ^ right
	count := 0
	for value != 0 {
		value &= value - 1
		count++
	}
	return count
}

func samePage(left, right page) bool {
	if left.StatusCode != right.StatusCode || left.ContentType != right.ContentType {
		return false
	}
	if left.NormalizedHash == right.NormalizedHash {
		return true
	}
	maximumLength := left.BodyLength
	if right.BodyLength > maximumLength {
		maximumLength = right.BodyLength
	}
	if maximumLength == 0 {
		return true
	}
	difference := left.BodyLength - right.BodyLength
	if difference < 0 {
		difference = -difference
	}
	allowedDifference := maximumLength / 20
	if allowedDifference < 32 {
		allowedDifference = 32
	}
	if difference > allowedDifference {
		return false
	}
	if left.NormalizedTitle != right.NormalizedTitle {
		return false
	}
	if left.StructureHash != "" && left.StructureHash == right.StructureHash &&
		difference <= maximumLength/5 {
		return true
	}
	if left.NormalizedTitle != "" {
		return true
	}
	if maximumLength <= 8*1024 {
		blankPageDifference := maximumLength / 50
		if blankPageDifference < 16 {
			blankPageDifference = 16
		}
		if difference <= blankPageDifference {
			return true
		}
	}
	return hammingDistance(left.Simhash, right.Simhash) <= 4
}

// sameStablePage is deliberately stricter than samePage. samePage detects a
// shared default template across different Host values, while this comparator
// verifies that repeated observations of one logical response stay stable.
func sameStablePage(left, right page) bool {
	if left.StatusCode != right.StatusCode || left.ContentType != right.ContentType {
		return false
	}
	if left.StabilityLocation != right.StabilityLocation {
		return false
	}
	if left.StabilityHash != "" && left.StabilityHash == right.StabilityHash {
		return true
	}
	if left.NormalizedTitle != right.NormalizedTitle {
		return false
	}
	maximumLength := left.StabilityLength
	if right.StabilityLength > maximumLength {
		maximumLength = right.StabilityLength
	}
	if maximumLength == 0 {
		return true
	}
	difference := left.StabilityLength - right.StabilityLength
	if difference < 0 {
		difference = -difference
	}
	allowedDifference := maximumLength / 50
	if allowedDifference < 16 {
		allowedDifference = 16
	}
	if difference > allowedDifference {
		return false
	}
	if left.StabilitySimhash == 0 || right.StabilitySimhash == 0 {
		return false
	}
	return hammingDistance(left.StabilitySimhash, right.StabilitySimhash) <= 3
}

func responseSignature(value page) string {
	structure := value.StructureHash
	if structure == "" {
		structure = fmt.Sprintf("%016x", value.Simhash)
	}
	payload := fmt.Sprintf(
		"%d|%s|%s|%s",
		value.StatusCode,
		value.ContentType,
		value.NormalizedTitle,
		structure,
	)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

func resultQuality(value page, confidence string) string {
	if confidence == "redirect" {
		return "high"
	}
	title := strings.ToLower(strings.TrimSpace(value.Title))
	if title == "" {
		return "medium"
	}
	defaultTitles := []string{
		"welcome to nginx", "apache2 ubuntu default page", "iis windows server",
		"http server test page", "test page for the nginx http server",
	}
	for _, fragment := range defaultTitles {
		if strings.Contains(title, fragment) {
			return "low"
		}
	}
	return "high"
}

func verificationState(statusCode int) string {
	if statusCode == http.StatusOK {
		return "confirmed"
	}
	return "restricted_candidate"
}

func textLike(value page) bool {
	if strings.Contains(value.ContentType, "text") || strings.Contains(value.ContentType, "html") ||
		strings.Contains(value.ContentType, "json") || strings.Contains(value.ContentType, "xml") {
		return true
	}
	prefix := bytes.ToLower(value.Body)
	if len(prefix) > 512 {
		prefix = prefix[:512]
	}
	return bytes.Contains(prefix, []byte("<html")) || bytes.Contains(prefix, []byte("<!doctype")) || bytes.Contains(prefix, []byte("{"))
}

func genericTitle(title string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	if title == "" {
		return false
	}
	fragments := []string{
		"access denied", "forbidden", "not found", "bad gateway", "service unavailable",
		"moved permanently", "moved temporarily", "安全防护", "访问被拒绝", "请求拦截", "waf",
	}
	for _, fragment := range fragments {
		if strings.Contains(title, fragment) {
			return true
		}
	}
	return false
}

func redirectMatches(location, domain string) bool {
	location = strings.TrimSpace(location)
	if location == "" {
		return false
	}
	if parsed, err := url.Parse(location); err == nil && parsed.Hostname() != "" {
		host := normalizeDomain(parsed.Hostname())
		return host == domain || strings.HasSuffix(host, "."+domain) || strings.HasSuffix(domain, "."+host)
	}
	return strings.Contains(strings.ToLower(location), domain)
}

func validPage(
	value page,
	domain string,
	baselines []page,
	minBodyLength int,
	acceptRedirect bool,
) (bool, string) {
	for _, baseline := range baselines {
		if samePage(value, baseline) {
			return false, ""
		}
	}

	if value.StatusCode == http.StatusMovedPermanently || value.StatusCode == http.StatusFound ||
		value.StatusCode == http.StatusSeeOther || value.StatusCode == http.StatusTemporaryRedirect ||
		value.StatusCode == http.StatusPermanentRedirect {
		if acceptRedirect && redirectMatches(value.Location, domain) {
			return true, "redirect"
		}
		return false, ""
	}

	if value.StatusCode != http.StatusOK {
		return false, ""
	}
	if !textLike(value) {
		return false, ""
	}
	confidence := "strict_200"
	if value.BodyLength < minBodyLength {
		return false, ""
	}
	if parkingPattern.Match(value.Body) || parkingPattern.MatchString(value.Title) {
		return false, ""
	}
	if value.StatusCode == http.StatusOK && genericTitle(value.Title) {
		return false, ""
	}
	return true, confidence
}

func hostHeaderVariants(domain string, ep endpoint) []string {
	defaultPort := (ep.Scheme == "http" && ep.Port == 80) || (ep.Scheme == "https" && ep.Port == 443)
	if defaultPort {
		return []string{domain}
	}
	return []string{fmt.Sprintf("%s:%d", domain, ep.Port), domain}
}

func (s *scanner) verificationControl(domain string) string {
	baseDomain := normalizeDomain(s.config.BaseDomain)
	if baseDomain != "" {
		control := "arl-control-verify." + baseDomain
		if control != normalizeDomain(domain) {
			return control
		}
	}
	return "arl-control-verify.invalid"
}

func retryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (s *scanner) fetchWithRetry(
	ctx context.Context,
	ep endpoint,
	domain, hostHeader, path string,
	transport *http.Transport,
	stats *scanStats,
) (*page, error) {
	var lastErr error
	for attempt := 0; attempt <= s.config.Retries; attempt++ {
		value, err := s.fetch(ctx, ep, domain, hostHeader, path, transport, stats)
		if err == nil {
			if value != nil && retryableStatus(value.StatusCode) && attempt < s.config.Retries {
				continue
			}
			return value, nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) {
			break
		}
	}
	s.errors.Add(1)
	stats.errors.Add(1)
	return nil, lastErr
}

type probeOutcome struct {
	result         *result
	unstable       bool
	verifiedStable bool
}

func (s *scanner) probeHost(
	ctx context.Context,
	ep endpoint,
	domain string,
	baselines []page,
	sharedTransport *http.Transport,
	stats *scanStats,
) probeOutcome {
	transport := sharedTransport
	if transport == nil {
		transport = s.transport(ep, domain)
		defer transport.CloseIdleConnections()
	}

	paths := []string{"/"}
	for _, value := range s.config.Paths[domain] {
		value = normalizePath(value)
		if value == "/" {
			continue
		}
		paths = append(paths, value)
		if len(paths)-1 >= s.config.PathLimit {
			break
		}
	}

	for pathIndex, path := range paths {
		for hostIndex, hostHeader := range hostHeaderVariants(domain, ep) {
			stabilityChecks := 0
			value, err := s.fetchWithRetry(
				ctx, ep, domain, hostHeader, path, transport, stats)
			if err != nil || value == nil {
				continue
			}
			matchedBaselines := baselines
			valid, confidence := validPage(
				*value,
				domain,
				matchedBaselines,
				s.config.MinBodyLength,
				s.config.AcceptRedirect,
			)
			if valid && path != "/" {
				pathBaselines := s.buildBaselines(ctx, ep, domain, path, stats)
				matchedBaselines = pathBaselines
				valid, confidence = validPage(
					*value,
					domain,
					matchedBaselines,
					s.config.MinBodyLength,
					s.config.AcceptRedirect,
				)
			}
			if valid {
				controlDomain := s.verificationControl(domain)
				controlHeaders := hostHeaderVariants(controlDomain, ep)
				controlHeader := controlHeaders[0]
				if hostIndex < len(controlHeaders) {
					controlHeader = controlHeaders[hostIndex]
				}
				control, controlErr := s.fetchWithRetry(
					ctx,
					ep,
					controlDomain,
					controlHeader,
					path,
					transport,
					stats,
				)
				if controlErr == nil && control != nil && samePage(*value, *control) {
					valid = false
				}
			}
			if valid && value.StatusCode == http.StatusOK {
				repeat, repeatErr := s.fetchWithRetry(
					ctx,
					ep,
					domain,
					hostHeader,
					path,
					transport,
					stats,
				)
				stabilityChecks = 2
				if repeatErr != nil || repeat == nil {
					valid = false
				} else if !sameStablePage(*value, *repeat) {
					return probeOutcome{unstable: true}
				}
			}
			if valid {
				return probeOutcome{result: &result{
					URL:               ep.key() + value.Path,
					Domain:            domain,
					IP:                ep.IP,
					Port:              ep.Port,
					Scheme:            ep.Scheme,
					Path:              value.Path,
					HostHeader:        hostHeader,
					SNI:               domain,
					Title:             value.Title,
					StatusCode:        value.StatusCode,
					BodyLength:        value.BodyLength,
					RedirectLocation:  value.Location,
					Confidence:        confidence,
					Quality:           resultQuality(*value, confidence),
					VerificationState: verificationState(value.StatusCode),
					ResponseSignature: responseSignature(*value),
					EndpointSources:   ep.Sources,
					BaselineCount:     len(matchedBaselines),
					StabilityChecks:   stabilityChecks,
					BodyTruncated:     value.Truncated,
				}, verifiedStable: value.StatusCode == http.StatusOK}
			}
		}
		// Real paths are a fallback for a root response that did not identify a vhost.
		if pathIndex == 0 && len(paths) == 1 {
			break
		}
	}
	return probeOutcome{}
}

func (s *scanner) buildBaselines(
	ctx context.Context,
	ep endpoint,
	firstDomain, path string,
	stats *scanStats,
) []page {
	controls := []string{
		ep.IP,
		"arl-control-one.invalid",
		"arl-control-two.invalid",
		"n0ta." + firstDomain,
	}
	baseDomain := normalizeDomain(s.config.BaseDomain)
	if baseDomain != "" {
		controls = append(
			controls,
			"arl-control-one."+baseDomain,
			"arl-control-two."+baseDomain,
		)
	}
	controls = dedupeStrings(controls)
	baselineCh := make(chan page, len(controls))
	var waitGroup sync.WaitGroup
	for _, host := range controls {
		host := host
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			serverName := host
			if net.ParseIP(host) != nil {
				serverName = ""
			}
			transport := s.transport(ep, serverName)
			defer transport.CloseIdleConnections()
			value, err := s.fetchWithRetry(
				ctx, ep, host, hostHeaderVariants(host, ep)[0], path, transport, stats)
			if err == nil && value != nil {
				baselineCh <- *value
			}
		}()
	}
	waitGroup.Wait()
	close(baselineCh)
	baselines := make([]page, 0, len(controls))
	for value := range baselineCh {
		baselines = append(baselines, value)
	}
	return baselines
}

const (
	dynamicOracleAttempts      = 4
	dynamicOracleMinSamples    = 3
	dynamicOracleEntropyHosts  = 3
	runtimeOracleTripThreshold = 3
)

func largestSimilarCluster(values []page) int {
	largest := 0
	for candidate := range values {
		clusterSize := 1
		for other := range values {
			if candidate != other && sameStablePage(values[candidate], values[other]) {
				clusterSize++
			}
		}
		if clusterSize > largest {
			largest = clusterSize
		}
	}
	return largest
}

func (s *scanner) entropyControlDomains() []string {
	suffix := "invalid"
	if baseDomain := normalizeDomain(s.config.BaseDomain); baseDomain != "" {
		suffix = baseDomain
	}
	controls := make([]string, 0, dynamicOracleEntropyHosts)
	for sample := 0; sample < dynamicOracleEntropyHosts; sample++ {
		controls = append(controls, fmt.Sprintf(
			"arl-entropy-%d-%x.%s", sample+1, sample*7919+104729, suffix))
	}
	return controls
}

func (s *scanner) dynamicResponseOracle(
	ctx context.Context,
	ep endpoint,
	path string,
	stats *scanStats,
) string {
	controlDomain := "arl-stability-control.invalid"
	baseDomain := normalizeDomain(s.config.BaseDomain)
	if baseDomain != "" {
		controlDomain = "arl-stability-control." + baseDomain
	}
	transport := s.transport(ep, controlDomain)
	defer transport.CloseIdleConnections()
	values := make([]page, 0, dynamicOracleAttempts)
	for sample := 0; sample < dynamicOracleAttempts; sample++ {
		value, err := s.fetchWithRetry(
			ctx,
			ep,
			controlDomain,
			hostHeaderVariants(controlDomain, ep)[0],
			path,
			transport,
			stats,
		)
		if err == nil && value != nil {
			values = append(values, *value)
		}
	}
	if len(values) == 0 {
		return "http_unreachable"
	}
	if len(values) < dynamicOracleMinSamples {
		return "insufficient_control_samples"
	}
	requiredCluster := len(values) - 1
	if largestSimilarCluster(values) < requiredCluster {
		return "dynamic_response_oracle"
	}

	entropyValues := make([]page, 0, dynamicOracleEntropyHosts)
	for _, entropyDomain := range s.entropyControlDomains() {
		entropyTransport := s.transport(ep, entropyDomain)
		value, err := s.fetchWithRetry(
			ctx,
			ep,
			entropyDomain,
			hostHeaderVariants(entropyDomain, ep)[0],
			path,
			entropyTransport,
			stats,
		)
		entropyTransport.CloseIdleConnections()
		if err == nil && value != nil {
			entropyValues = append(entropyValues, *value)
		}
	}
	if len(entropyValues) >= 2 && largestSimilarCluster(entropyValues) != len(entropyValues) {
		return "dynamic_response_oracle"
	}
	return ""
}

type runtimeResponseOracle struct {
	mu                  sync.Mutex
	consecutiveUnstable int
	tripped             bool
}

func (o *runtimeResponseOracle) observeUnstable() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.tripped {
		return true
	}
	o.consecutiveUnstable++
	if o.consecutiveUnstable >= runtimeOracleTripThreshold {
		o.tripped = true
	}
	return o.tripped
}

func (o *runtimeResponseOracle) observeStable() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.tripped {
		o.consecutiveUnstable = 0
	}
}

func (o *runtimeResponseOracle) isTripped() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.tripped
}

func mergeDomains(global, targeted []string) []string {
	seen := make(map[string]struct{}, len(global)+len(targeted))
	values := make([]string, 0, len(global)+len(targeted))
	add := func(items []string) {
		for _, value := range items {
			value = normalizeDomain(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	add(targeted)
	add(global)
	return values
}

func (s *scanner) scanEndpoint(ctx context.Context, ep endpoint, globalDomains []string) {
	endpointKey := ep.key()
	skipped := false
	endpointError := ""
	stats := &scanStats{}
	s.emitter.emit(event{
		Type:           "start",
		EndpointKey:    endpointKey,
		TotalEndpoints: len(s.config.Endpoints),
	})
	defer func() {
		completed := s.completed.Add(1)
		s.emitter.emit(event{
			Type:               "progress",
			EndpointKey:        endpointKey,
			CompletedEndpoints: completed,
			TotalEndpoints:     len(s.config.Endpoints),
			RequestCount:       stats.requests.Load(),
			ResponseCount:      stats.responses.Load(),
			ErrorCount:         stats.errors.Load(),
			ResultCount:        stats.results.Load(),
			TotalRequestCount:  s.requests.Load(),
			TotalResponseCount: s.responses.Load(),
			TotalErrorCount:    s.errors.Load(),
			TotalResultCount:   s.results.Load(),
			Skipped:            skipped,
			Error:              endpointError,
		})
	}()

	if !s.tcpReady(ctx, ep) {
		skipped = true
		endpointError = "tcp_unreachable"
		return
	}
	domains := mergeDomains(globalDomains, ep.Domains)
	if len(domains) == 0 {
		skipped = true
		endpointError = "no_domains"
		return
	}
	baselines := s.buildBaselines(ctx, ep, domains[0], "/", stats)
	if reason := s.dynamicResponseOracle(ctx, ep, "/", stats); reason != "" {
		skipped = true
		endpointError = reason
		return
	}
	endpointCtx, cancelEndpoint := context.WithCancel(ctx)
	defer cancelEndpoint()
	var sharedTransport *http.Transport
	if ep.Scheme == "http" {
		sharedTransport = s.transport(ep, "")
		defer sharedTransport.CloseIdleConnections()
	}

	jobs := make(chan string)
	workerCount := s.config.HostConcurrency
	if workerCount > len(domains) {
		workerCount = len(domains)
	}
	if len(baselines) < 2 && workerCount > 4 {
		workerCount = 4
	}
	var workers sync.WaitGroup
	var resultMu sync.Mutex
	endpointResults := make([]*result, 0)
	runtimeOracle := &runtimeResponseOracle{}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for domain := range jobs {
				if runtimeOracle.isTripped() {
					return
				}
				outcome := s.probeHost(
					endpointCtx, ep, domain, baselines, sharedTransport, stats)
				if outcome.unstable {
					if runtimeOracle.observeUnstable() {
						cancelEndpoint()
					}
					continue
				}
				if outcome.result == nil {
					continue
				}
				if outcome.verifiedStable {
					runtimeOracle.observeStable()
				}
				resultMu.Lock()
				endpointResults = append(endpointResults, outcome.result)
				resultMu.Unlock()
			}
		}()
	}

feedDomains:
	for _, domain := range domains {
		select {
		case jobs <- domain:
		case <-endpointCtx.Done():
			break feedDomains
		}
	}
	close(jobs)
	workers.Wait()
	if runtimeOracle.isTripped() {
		skipped = true
		endpointError = "runtime_dynamic_response_oracle"
		return
	}
	if ctx.Err() != nil {
		endpointError = ctx.Err().Error()
		return
	}
	for _, value := range endpointResults {
		s.results.Add(1)
		stats.results.Add(1)
		s.emitter.emit(event{Type: "result", Result: value})
	}
	if stats.requests.Load() > 0 && stats.responses.Load() == 0 {
		endpointError = "http_unreachable"
	}
}

func run(ctx context.Context, config input, output io.Writer) error {
	defaults(&config)
	config.Domains = dedupeStrings(config.Domains)
	if len(config.Endpoints) == 0 {
		return errors.New("endpoints are required")
	}
	availableDomains := len(config.Domains)
	for _, ep := range config.Endpoints {
		availableDomains += len(ep.Domains)
	}
	if availableDomains == 0 {
		return errors.New("domains are required")
	}
	worker := &scanner{
		config:     config,
		emitter:    &emitter{enc: json.NewEncoder(output)},
		requestSem: make(chan struct{}, config.Concurrency),
	}

	jobs := make(chan endpoint)
	var endpoints sync.WaitGroup
	workerCount := config.EndpointConcurrency
	if workerCount > len(config.Endpoints) {
		workerCount = len(config.Endpoints)
	}
	for i := 0; i < workerCount; i++ {
		endpoints.Add(1)
		go func() {
			defer endpoints.Done()
			for ep := range jobs {
				worker.scanEndpoint(ctx, ep, config.Domains)
			}
		}()
	}
	for _, ep := range config.Endpoints {
		select {
		case jobs <- ep:
		case <-ctx.Done():
			close(jobs)
			endpoints.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	endpoints.Wait()
	worker.emitter.emit(event{
		Type:               "summary",
		CompletedEndpoints: worker.completed.Load(),
		TotalEndpoints:     len(config.Endpoints),
		RequestCount:       worker.requests.Load(),
		ResponseCount:      worker.responses.Load(),
		ErrorCount:         worker.errors.Load(),
		ResultCount:        worker.results.Load(),
		TotalRequestCount:  worker.requests.Load(),
		TotalResponseCount: worker.responses.Load(),
		TotalErrorCount:    worker.errors.Load(),
		TotalResultCount:   worker.results.Load(),
	})
	return nil
}

func main() {
	decoder := json.NewDecoder(bufio.NewReader(os.Stdin))
	var config input
	if err := decoder.Decode(&config); err != nil {
		fmt.Fprintln(os.Stderr, "decode input:", err)
		os.Exit(2)
	}
	if err := run(context.Background(), config, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
