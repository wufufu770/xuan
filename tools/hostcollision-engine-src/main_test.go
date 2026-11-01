package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func testEndpoint(t *testing.T, serverURL string) endpoint {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portValue, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portValue)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint{Scheme: parsed.Scheme, IP: host, Port: port, Sources: []string{"test"}}
}

func decodeEvents(t *testing.T, output []byte) []event {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(output))
	var events []event
	for decoder.More() {
		var value event
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		events = append(events, value)
	}
	return events
}

func resultEvents(values []event) []result {
	var output []result
	for _, value := range values {
		if value.Type == "result" && value.Result != nil {
			output = append(output, *value.Result)
		}
	}
	return output
}

func TestMergeDomainsPrioritizesTargetedEvidence(t *testing.T) {
	values := mergeDomains(
		[]string{"z.example.com", "a.example.com"},
		[]string{"old.example.com", "a.example.com"},
	)
	want := []string{"old.example.com", "a.example.com", "z.example.com"}
	if fmt.Sprint(values) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", values, want)
	}
}

func TestRetryableStatus(t *testing.T) {
	for _, statusCode := range []int{408, 429, 500, 502, 503, 504} {
		if !retryableStatus(statusCode) {
			t.Fatalf("status %d should retry", statusCode)
		}
	}
	if retryableStatus(404) {
		t.Fatal("404 should not retry")
	}
}

func TestRestrictedResponsesAreDiscarded(t *testing.T) {
	value := page{
		StatusCode:  http.StatusForbidden,
		ContentType: "text/plain",
		Body:        []byte(strings.Repeat("access denied ", 10)),
		BodyLength:  140,
	}
	valid, confidence := validPage(
		value, "target.example.com", nil, 300, true)
	if valid || confidence != "" {
		t.Fatalf("restricted response was accepted: valid=%v confidence=%q", valid, confidence)
	}
	if state := verificationState(value.StatusCode); state != "restricted_candidate" {
		t.Fatalf("restricted response was promoted: %q", state)
	}
}

func TestServerErrorsNeverBecomeHostMappings(t *testing.T) {
	for _, statusCode := range []int{502, 503, 504} {
		value := page{
			StatusCode:  statusCode,
			ContentType: "text/html",
			Body:        []byte(strings.Repeat("gateway error ", 50)),
			BodyLength:  700,
		}
		if valid, _ := validPage(value, "target.example.com", nil, 300, true); valid {
			t.Fatalf("status %d was accepted", statusCode)
		}
	}
}

func TestRunMarksHTTPUnreachableWhenTCPAcceptsButEveryRequestFails(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	host, portValue, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portValue)
	if err != nil {
		t.Fatal(err)
	}
	config := input{
		Endpoints:           []endpoint{{Scheme: "http", IP: host, Port: port}},
		Domains:             []string{"target.example.com"},
		Concurrency:         8,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    250,
		RequestTimeoutMS:    500,
		Retries:             0,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	for _, value := range decodeEvents(t, output.Bytes()) {
		if value.Type != "progress" {
			continue
		}
		if value.Error != "http_unreachable" {
			t.Fatalf("got error %q: %s", value.Error, output.String())
		}
		if value.RequestCount == 0 || value.ResponseCount != 0 {
			t.Fatalf("unexpected counters: %+v", value)
		}
		return
	}
	t.Fatalf("progress event missing: %s", output.String())
}

func TestRedirectRequiresExplicitEnableAndMatchingHost(t *testing.T) {
	value := page{
		StatusCode: http.StatusFound,
		Location:   "https://target.example.com/login",
	}
	valid, confidence := validPage(
		value, "target.example.com", nil, 300, true)
	if !valid || confidence != "redirect" {
		t.Fatalf("matching redirect rejected: valid=%v confidence=%q", valid, confidence)
	}
	if state := verificationState(value.StatusCode); state != "restricted_candidate" {
		t.Fatalf("redirect was promoted: %q", state)
	}
	valid, _ = validPage(value, "target.example.com", nil, 300, false)
	if valid {
		t.Fatal("disabled redirect was accepted")
	}
	value.Location = "https://outside.test/login"
	valid, _ = validPage(value, "target.example.com", nil, 300, true)
	if valid {
		t.Fatal("cross-domain redirect was accepted")
	}
}

func TestPageNormalizationIgnoresHostCase(t *testing.T) {
	firstResponse := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	secondResponse := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	first := newPage(
		firstResponse,
		[]byte("<html><title>TARGET.EXAMPLE.COM Portal</title></html>"),
		"target.example.com",
		"/",
		false,
	)
	second := newPage(
		secondResponse,
		[]byte("<html><title>OTHER.EXAMPLE.COM Portal</title></html>"),
		"other.example.com",
		"/",
		false,
	)
	if !samePage(first, second) {
		t.Fatalf("host-specific default pages did not normalize: %#v %#v", first, second)
	}
}

func TestSamePageUsesHTMLStructureForDynamicTemplates(t *testing.T) {
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	first := newPage(
		response,
		[]byte("<html><head><title>Shared Login</title></head><body><form><input value='token-a-1234567890'></form></body></html>"),
		"target.example.com",
		"/",
		false,
	)
	second := newPage(
		response,
		[]byte("<html><head><title>Shared Login</title></head><body><form><input value='completely-different-token-b-0987654321'></form></body></html>"),
		"arl-control.example.com",
		"/",
		false,
	)
	if !samePage(first, second) {
		t.Fatalf("dynamic shared template was not normalized: %#v %#v", first, second)
	}
}

func TestStablePageRejectsSameTitleAndStructureWithDifferentContent(t *testing.T) {
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	first := newPage(
		response,
		[]byte("<html><title>Shared Gateway</title><body><main>"+strings.Repeat("alpha-service ", 80)+"</main></body></html>"),
		"first.example.com",
		"/",
		false,
	)
	second := newPage(
		response,
		[]byte("<html><title>Shared Gateway</title><body><main>"+strings.Repeat("omega-systemx ", 80)+"</main></body></html>"),
		"second.example.com",
		"/",
		false,
	)
	if !samePage(first, second) {
		t.Fatal("fixture should exercise the tolerant default-template comparator")
	}
	if sameStablePage(first, second) {
		t.Fatal("same title and HTML structure hid different response bodies")
	}
}

func TestStablePageNormalizesVolatileTokens(t *testing.T) {
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	first := newPage(
		response,
		[]byte("<html><title>Login 1711111111</title><body><input value='0f6f973e-5d87-4a2b-b59d-4f2ebfc50a11'>Welcome</body></html>"),
		"target.example.com",
		"/",
		false,
	)
	second := newPage(
		response,
		[]byte("<html><title>Login 1722222222</title><body><input value='c4aa9acc-3bb3-4aa5-94f6-b27b93f6113c'>Welcome</body></html>"),
		"target.example.com",
		"/",
		false,
	)
	if !sameStablePage(first, second) {
		t.Fatal("volatile timestamp and token made a stable page look unstable")
	}
}

func TestSamePageTreatsSmallUntitledNearLengthAsDynamic(t *testing.T) {
	response := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	first := newPage(
		response,
		[]byte("<html><body><form><input value='one'></form>"+strings.Repeat("a", 2200)+"</body></html>"),
		"target.example.com",
		"/",
		false,
	)
	second := newPage(
		response,
		[]byte("<html><main><section><p>two</p></section>"+strings.Repeat("z", 2204)+"</main></html>"),
		"arl-control.example.com",
		"/",
		false,
	)
	if !samePage(first, second) {
		t.Fatalf("small untitled dynamic pages were not matched: %#v %#v", first, second)
	}
}

func TestRunRejectsSameRootWildcardTemplate(t *testing.T) {
	var requestCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		labels := strings.Count(host, ".")
		if strings.HasSuffix(host, ".example.com") && labels == 2 {
			value := requestCount.Add(1)
			_, _ = writer.Write([]byte(fmt.Sprintf(
				"<html><head><title>Shared Gateway</title></head><body><form><input value='%s-%d'></form>%s</body></html>",
				host, value, strings.Repeat("shared ", 80))))
			return
		}
		writer.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()

	ep := testEndpoint(t, server.URL)
	config := input{
		Endpoints:           []endpoint{ep},
		Domains:             []string{"target.example.com"},
		BaseDomain:          "example.com",
		Concurrency:         16,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	if results := resultEvents(decodeEvents(t, output.Bytes())); len(results) != 0 {
		t.Fatalf("same-root wildcard template produced results: %+v", results)
	}
}

func TestRunRejectsDynamicResponseOracle(t *testing.T) {
	var requestCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := requestCount.Add(1)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(fmt.Sprintf(
			"<html><title>Rotating System %d</title><body>%s</body></html>",
			value, strings.Repeat(fmt.Sprintf("response-%d ", value), 80))))
	}))
	defer server.Close()

	ep := testEndpoint(t, server.URL)
	config := input{
		Endpoints:           []endpoint{ep},
		Domains:             []string{"target.example.com"},
		BaseDomain:          "example.com",
		Concurrency:         16,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	values := decodeEvents(t, output.Bytes())
	if results := resultEvents(values); len(results) != 0 {
		t.Fatalf("dynamic response oracle produced results: %+v", results)
	}
	for _, value := range values {
		if value.Type == "progress" {
			if value.Error != "dynamic_response_oracle" || !value.Skipped {
				t.Fatalf("unexpected progress: %+v", value)
			}
			return
		}
	}
	t.Fatalf("progress event missing: %s", output.String())
}

func TestRunRejectsCrossHostDynamicResponseOracle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(host, "arl-entropy-") {
			content := "alpha-service"
			if strings.Contains(host, "entropy-2-") {
				content = "beta-console"
			} else if strings.Contains(host, "entropy-3-") {
				content = "gamma-portal"
			}
			_, _ = writer.Write([]byte(
				"<html><title>Shared Gateway</title><body><main>" +
					strings.Repeat(content+" ", 80) +
					"</main></body></html>"))
			return
		}
		_, _ = writer.Write([]byte(
			"<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run(context.Background(), input{
		Endpoints: []endpoint{testEndpoint(t, server.URL)}, Domains: []string{"target.example.com"},
		BaseDomain: "example.com", Concurrency: 16, EndpointConcurrency: 1, HostConcurrency: 1,
		ConnectTimeoutMS: 500, RequestTimeoutMS: 1000, MinBodyLength: 100,
	}, &output); err != nil {
		t.Fatal(err)
	}
	for _, value := range decodeEvents(t, output.Bytes()) {
		if value.Type == "progress" {
			if value.Error != "dynamic_response_oracle" || !value.Skipped {
				t.Fatalf("unexpected progress: %+v", value)
			}
			return
		}
	}
	t.Fatalf("cross-host dynamic endpoint was not rejected: %s", output.String())
}

func TestRunTripsRuntimeOracleAfterThreeUnstableCandidates(t *testing.T) {
	var candidateRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(host, "candidate-") {
			value := candidateRequests.Add(1)
			_, _ = writer.Write([]byte(
				"<html><title>Internal Console</title><body><main>" +
					strings.Repeat(fmt.Sprintf("random-system-%d ", value), 80) +
					"</main></body></html>"))
			return
		}
		_, _ = writer.Write([]byte(
			"<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run(context.Background(), input{
		Endpoints: []endpoint{testEndpoint(t, server.URL)},
		Domains: []string{
			"candidate-1.example.com", "candidate-2.example.com",
			"candidate-3.example.com", "candidate-4.example.com",
		},
		BaseDomain: "example.com", Concurrency: 16, EndpointConcurrency: 1, HostConcurrency: 1,
		ConnectTimeoutMS: 500, RequestTimeoutMS: 1000, MinBodyLength: 100,
	}, &output); err != nil {
		t.Fatal(err)
	}
	events := decodeEvents(t, output.Bytes())
	if results := resultEvents(events); len(results) != 0 {
		t.Fatalf("runtime oracle leaked buffered results: %+v", results)
	}
	for _, value := range events {
		if value.Type == "progress" {
			if value.Error != "runtime_dynamic_response_oracle" || !value.Skipped {
				t.Fatalf("unexpected progress: %+v", value)
			}
			if candidateRequests.Load() != runtimeOracleTripThreshold*2 {
				t.Fatalf("candidate requests=%d, want %d", candidateRequests.Load(), runtimeOracleTripThreshold*2)
			}
			return
		}
	}
	t.Fatalf("runtime oracle did not trip: %s", output.String())
}

func TestLargestSimilarClusterRejectsOnlyOneMatchingPair(t *testing.T) {
	values := []page{
		{StatusCode: 200, ContentType: "text/html", NormalizedHash: "same", BodyLength: 400},
		{StatusCode: 200, ContentType: "text/html", NormalizedHash: "same", BodyLength: 400},
		{StatusCode: 200, ContentType: "text/html", NormalizedHash: "third", NormalizedTitle: "third", BodyLength: 600},
		{StatusCode: 200, ContentType: "text/html", NormalizedHash: "fourth", NormalizedTitle: "fourth", BodyLength: 800},
		{StatusCode: 200, ContentType: "text/html", NormalizedHash: "fifth", NormalizedTitle: "fifth", BodyLength: 1000},
	}
	if cluster := largestSimilarCluster(values); cluster != 2 {
		t.Fatalf("largest cluster=%d, want 2", cluster)
	}
}

func TestRunRejectsFiveSamplesWithOnlyTwoStable(t *testing.T) {
	var controlRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(host, "arl-stability-control.") {
			value := controlRequests.Add(1)
			if value <= 2 {
				_, _ = writer.Write([]byte("<html><title>Pair</title><body>" + strings.Repeat("pair ", 80) + "</body></html>"))
				return
			}
			_, _ = writer.Write([]byte(fmt.Sprintf(
				"<html><title>Rotating %d</title><body>%s</body></html>",
				value, strings.Repeat(fmt.Sprintf("page-%d ", value), 80))))
			return
		}
		_, _ = writer.Write([]byte("<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run(context.Background(), input{
		Endpoints: []endpoint{testEndpoint(t, server.URL)}, Domains: []string{"target.example.com"},
		BaseDomain: "example.com", Concurrency: 16, EndpointConcurrency: 1, HostConcurrency: 1,
		ConnectTimeoutMS: 500, RequestTimeoutMS: 1000, MinBodyLength: 100,
	}, &output); err != nil {
		t.Fatal(err)
	}
	for _, value := range decodeEvents(t, output.Bytes()) {
		if value.Type == "progress" && value.Error == "dynamic_response_oracle" && value.Skipped {
			if controlRequests.Load() != dynamicOracleAttempts {
				t.Fatalf("control requests=%d, want %d", controlRequests.Load(), dynamicOracleAttempts)
			}
			return
		}
	}
	t.Fatalf("endpoint was not rejected: %s", output.String())
}

func TestRunAllowsFourSamplesWithThreeStable(t *testing.T) {
	var controlRequests atomic.Int64
	stableDefault := "<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"
	targetBody := "<html><title>Internal Console</title><body>" + strings.Repeat("private ", 80) + "</body></html>"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(host, "arl-stability-control.") {
			value := controlRequests.Add(1)
			switch value {
			case 4:
				_, _ = writer.Write([]byte("<html><title>Alternate</title><body>" + strings.Repeat("alternate ", 80) + "</body></html>"))
			case 5:
				hijacker, ok := writer.(http.Hijacker)
				if !ok {
					t.Error("test server does not support hijacking")
					return
				}
				connection, _, err := hijacker.Hijack()
				if err != nil {
					t.Errorf("hijack failed: %v", err)
					return
				}
				_ = connection.Close()
			default:
				_, _ = writer.Write([]byte(stableDefault))
			}
			return
		}
		if host == "target.example.com" {
			_, _ = writer.Write([]byte(targetBody))
			return
		}
		_, _ = writer.Write([]byte(stableDefault))
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run(context.Background(), input{
		Endpoints: []endpoint{testEndpoint(t, server.URL)}, Domains: []string{"target.example.com"},
		BaseDomain: "example.com", Concurrency: 16, EndpointConcurrency: 1, HostConcurrency: 1,
		ConnectTimeoutMS: 500, RequestTimeoutMS: 1000, MinBodyLength: 100,
	}, &output); err != nil {
		t.Fatal(err)
	}
	results := resultEvents(decodeEvents(t, output.Bytes()))
	if len(results) != 1 || results[0].Domain != "target.example.com" {
		t.Fatalf("stable 3-of-4 endpoint results=%+v: %s", results, output.String())
	}
}

func TestRunAllowsStableTemplateWithDynamicToken(t *testing.T) {
	var token atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if host == "target.example.com" {
			_, _ = writer.Write([]byte("<html><title>Internal Console</title><body>" + strings.Repeat("private ", 80) + "</body></html>"))
			return
		}
		_, _ = writer.Write([]byte(fmt.Sprintf(
			"<html><title>Default</title><body><input value='token-%d'>%s</body></html>",
			token.Add(1), strings.Repeat("default ", 80))))
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run(context.Background(), input{
		Endpoints: []endpoint{testEndpoint(t, server.URL)}, Domains: []string{"target.example.com"},
		BaseDomain: "example.com", Concurrency: 16, EndpointConcurrency: 1, HostConcurrency: 1,
		ConnectTimeoutMS: 500, RequestTimeoutMS: 1000, MinBodyLength: 100,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if results := resultEvents(decodeEvents(t, output.Bytes())); len(results) != 1 {
		t.Fatalf("stable tokenized endpoint results=%+v: %s", results, output.String())
	}
}

func TestRunRejectsCandidateThatChangesOnConfirmation(t *testing.T) {
	var candidateRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if host == "target.example.com" {
			value := candidateRequests.Add(1)
			_, _ = writer.Write([]byte(fmt.Sprintf(
				"<html><title>Console %d</title><body>%s</body></html>",
				value, strings.Repeat(fmt.Sprintf("candidate-%d ", value), 80))))
			return
		}
		_, _ = writer.Write([]byte("<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
	}))
	defer server.Close()

	var output bytes.Buffer
	if err := run(context.Background(), input{
		Endpoints: []endpoint{testEndpoint(t, server.URL)}, Domains: []string{"target.example.com"},
		BaseDomain: "example.com", Concurrency: 16, EndpointConcurrency: 1, HostConcurrency: 1,
		ConnectTimeoutMS: 500, RequestTimeoutMS: 1000, MinBodyLength: 100,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if results := resultEvents(decodeEvents(t, output.Bytes())); len(results) != 0 {
		t.Fatalf("unstable candidate produced results=%+v", results)
	}
	if candidateRequests.Load() < 2 || candidateRequests.Load()%2 != 0 {
		t.Fatalf("candidate requests=%d, want paired initial and confirmation requests", candidateRequests.Load())
	}
}

func TestRunConfirmsPotentialHitWithSameConnectionControl(t *testing.T) {
	var requestCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if host == "target.example.com" || host == "arl-control-verify.example.com" {
			value := requestCount.Add(1)
			_, _ = writer.Write([]byte(fmt.Sprintf(
				"<html><title>Dynamic Gateway</title><body><form><input value='%s-%d'></form>%s</body></html>",
				host, value, strings.Repeat("shared ", 80))))
			return
		}
		writer.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()

	ep := testEndpoint(t, server.URL)
	config := input{
		Endpoints:           []endpoint{ep},
		Domains:             []string{"target.example.com"},
		BaseDomain:          "example.com",
		Concurrency:         16,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	if results := resultEvents(decodeEvents(t, output.Bytes())); len(results) != 0 {
		t.Fatalf("paired wildcard control produced results: %+v", results)
	}
}

func TestVerificationControlUsesMatchingHostHeaderVariant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if request.Host == "target.example.com" ||
			request.Host == "arl-control-verify.example.com" {
			_, _ = writer.Write([]byte(
				"<html><title>Shared</title><body>" + strings.Repeat("shared ", 80) + "</body></html>"))
			return
		}
		writer.WriteHeader(http.StatusTeapot)
	}))
	defer server.Close()

	ep := testEndpoint(t, server.URL)
	config := input{
		Endpoints:           []endpoint{ep},
		Domains:             []string{"target.example.com"},
		BaseDomain:          "example.com",
		Concurrency:         16,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	if results := resultEvents(decodeEvents(t, output.Bytes())); len(results) != 0 {
		t.Fatalf("host header variant bypassed control: %+v", results)
	}
}

func TestProgressCountersAreEndpointScoped(t *testing.T) {
	newServer := func(title string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			host := strings.Split(request.Host, ":")[0]
			writer.Header().Set("Content-Type", "text/html")
			if host == "target.example.com" {
				_, _ = writer.Write([]byte(
					"<html><title>" + title + "</title><body>" + strings.Repeat("private ", 80) + "</body></html>"))
				return
			}
			_, _ = writer.Write([]byte(
				"<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
		}))
	}
	firstServer := newServer("First App")
	defer firstServer.Close()
	secondServer := newServer("Second App")
	defer secondServer.Close()

	config := input{
		Endpoints: []endpoint{
			testEndpoint(t, firstServer.URL),
			testEndpoint(t, secondServer.URL),
		},
		Domains:             []string{"target.example.com"},
		BaseDomain:          "example.com",
		Concurrency:         16,
		EndpointConcurrency: 2,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	events := decodeEvents(t, output.Bytes())
	var progressRequests int64
	var summary event
	progressCount := 0
	for _, value := range events {
		if value.Type == "progress" {
			progressCount++
			progressRequests += value.RequestCount
		}
		if value.Type == "summary" {
			summary = value
		}
	}
	if progressCount != 2 {
		t.Fatalf("got %d progress events: %s", progressCount, output.String())
	}
	if progressRequests != summary.RequestCount {
		t.Fatalf("endpoint requests %d != total requests %d", progressRequests, summary.RequestCount)
	}
	if summary.TotalRequestCount != summary.RequestCount {
		t.Fatalf("summary total request mismatch: %+v", summary)
	}
}

func TestRunFindsHostOnRealPathAfterTransientResponse(t *testing.T) {
	var candidateRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		writer.Header().Set("Content-Type", "text/html")
		if host == "target.example.com" && request.URL.Path == "/admin" {
			if candidateRequests.Add(1) == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte("<html><title>temporary</title></html>"))
				return
			}
			_, _ = writer.Write([]byte(
				"<html><title>Private Admin</title><body>" + strings.Repeat("private ", 80) + "</body></html>"))
			return
		}
		_, _ = writer.Write([]byte(
			"<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
	}))
	defer server.Close()

	ep := testEndpoint(t, server.URL)
	config := input{
		Endpoints:           []endpoint{ep},
		Domains:             []string{"target.example.com"},
		Paths:               map[string][]string{"target.example.com": {"/admin"}},
		Concurrency:         16,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
		AcceptRedirect:      true,
		PathLimit:           1,
		Retries:             1,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	results := resultEvents(decodeEvents(t, output.Bytes()))
	if len(results) != 1 {
		t.Fatalf("got %d results: %s", len(results), output.String())
	}
	if results[0].Path != "/admin" || results[0].Domain != "target.example.com" {
		t.Fatalf("unexpected result: %+v", results[0])
	}
	if candidateRequests.Load() != 3 {
		t.Fatalf("transient response was not retried: %d requests", candidateRequests.Load())
	}
}

func TestRunRejectsGenericContentOnRealPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		if request.URL.Path == "/admin" {
			_, _ = writer.Write([]byte(
				"<html><title>Shared Admin</title><body>" + strings.Repeat("shared ", 80) + "</body></html>"))
			return
		}
		_, _ = writer.Write([]byte(
			"<html><title>Default</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
	}))
	defer server.Close()

	ep := testEndpoint(t, server.URL)
	config := input{
		Endpoints:           []endpoint{ep},
		Domains:             []string{"target.example.com"},
		Paths:               map[string][]string{"target.example.com": {"/admin"}},
		Concurrency:         16,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
		AcceptRedirect:      true,
		PathLimit:           1,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	if results := resultEvents(decodeEvents(t, output.Bytes())); len(results) != 0 {
		t.Fatalf("generic path produced results: %+v", results)
	}
}

func TestRunSendsCandidateSNIAndHost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.Split(request.Host, ":")[0]
		serverName := ""
		if request.TLS != nil {
			serverName = request.TLS.ServerName
		}
		writer.Header().Set("Content-Type", "text/html")
		if host == "target.example.com" && serverName == "target.example.com" {
			_, _ = writer.Write([]byte(
				"<html><title>Private TLS App</title><body>" + strings.Repeat("private ", 80) + "</body></html>"))
			return
		}
		_, _ = writer.Write([]byte(
			"<html><title>Default TLS</title><body>" + strings.Repeat("default ", 80) + "</body></html>"))
	}))
	defer server.Close()

	ep := testEndpoint(t, server.URL)
	config := input{
		Endpoints:           []endpoint{ep},
		Domains:             []string{"target.example.com"},
		Concurrency:         16,
		EndpointConcurrency: 1,
		HostConcurrency:     1,
		ConnectTimeoutMS:    500,
		RequestTimeoutMS:    1000,
		MinBodyLength:       100,
	}
	var output bytes.Buffer
	if err := run(context.Background(), config, &output); err != nil {
		t.Fatal(err)
	}
	results := resultEvents(decodeEvents(t, output.Bytes()))
	if len(results) != 1 {
		t.Fatalf("got %d results: %s", len(results), output.String())
	}
	if results[0].SNI != "target.example.com" ||
		!strings.HasPrefix(results[0].HostHeader, "target.example.com") {
		t.Fatalf("candidate SNI/Host missing: %+v", results[0])
	}
	if results[0].Quality != "high" || results[0].ResponseSignature == "" {
		t.Fatalf("quality/signature missing: %+v", results[0])
	}
	if results[0].StabilityChecks != 2 {
		t.Fatalf("candidate stability was not verified: %+v", results[0])
	}
}
