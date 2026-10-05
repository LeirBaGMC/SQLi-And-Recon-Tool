package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/LeirBaGMC/sql-scanner/models"
)

func TestLiveAuthorizedTarget(t *testing.T) {
	if os.Getenv("RUN_AUTHORIZED_LIVE_TEST") != "1" {
		t.Skip("live target test is opt-in")
	}
	client, err := authorizedClient("http://testphp.vulnweb.com/listproducts.php?cat=1")
	if err != nil {
		t.Fatal(err)
	}
	events, err := probeAuthorizedCandidate(client, DiscoveryCandidate{URL: "http://testphp.vulnweb.com/listproducts.php?cat=1", ParameterName: "cat", OriginalValue: "1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		t.Logf("%s: result=%s HTTP=%d baseline_bytes=%d observed_bytes=%d reason=%s", event.Name, event.Result, event.StatusCode, event.BaselineSize, event.ObservedSize, event.Reason)
	}
}

func TestAuthorizedProbesRealHTTP(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Query().Get("cat") {
		case "1'":
			w.WriteHeader(500)
			_, _ = w.Write([]byte("You have an error in your SQL syntax"))
		case "1 AND 1=2":
			_, _ = w.Write([]byte("empty catalog"))
		default:
			_, _ = w.Write([]byte("catalog"))
		}
	}))
	defer server.Close()
	events, err := probeAuthorizedCandidate(server.Client(), DiscoveryCandidate{URL: server.URL + "?cat=1", ParameterName: "cat", OriginalValue: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 7 || len(events) != 2 {
		t.Fatalf("requests=%d events=%d", requests, len(events))
	}
	for _, event := range events {
		if event.ExecutionType != "REAL" || event.Result != "DETECTED" {
			t.Fatalf("unexpected event: %+v", event)
		}
	}
}

func TestAuthorizedProbesDoNotDetectStableSecureResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("stable catalog")) }))
	defer server.Close()
	events, err := probeAuthorizedCandidate(server.Client(), DiscoveryCandidate{URL: server.URL + "?cat=1", ParameterName: "cat", OriginalValue: "1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Result != "NOT_DETECTED" {
			t.Fatalf("unexpected detection: %+v", event)
		}
	}
}

func TestTextProbeExplainsMutationAndNegativeResult(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("same-size-changed-%t", changed), func(t *testing.T) {
			var queries []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				queries = append(queries, r.URL.RawQuery)
				body := "AAAA"
				if changed && r.URL.Query().Get("flag") == "failed'" {
					body = "BBBB"
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			var activity []models.LabActivityEvent
			events, err := probeAuthorizedCandidateWithTrace(server.Client(), DiscoveryCandidate{URL: server.URL + "?flag=failed", ParameterName: "flag", OriginalValue: "failed"}, "text", 0, 3, func(event models.LabActivityEvent) { activity = append(activity, event) })
			if err != nil || len(events) != 1 || len(queries) != 3 || queries[2] != "flag=failed%27" {
				t.Fatalf("queries=%v events=%+v err=%v", queries, events, err)
			}
			event := events[0]
			if event.Result != "NOT_DETECTED" || event.OriginalValue == nil || *event.OriginalValue != "failed" || event.Payload != "failed'" || event.EncodedQuery != queries[2] || event.FinalURL != server.URL+"?"+queries[2] || event.CoverageNote == "" {
				t.Fatalf("missing diagnostic: %+v", event)
			}
			checks := map[string]string{}
			for _, check := range event.Checks {
				checks[check.Label] = check.Value
			}
			if checks["Contenido idéntico a la base"] != yesNo(!changed) || checks["Diferencia de tamaño"] != "+0 bytes" || checks["Firma SQL nueva frente a ambas bases"] != "No" {
				t.Fatalf("byte equality must not imply identical body: %+v", checks)
			}
			if len(activity) != 7 || activity[6].State != "skipped" || activity[6].Stage != "coverage" || activity[5].Checks[0].Value != yesNo(!changed) {
				t.Fatalf("missing request comparison / skipped probe: %+v", activity)
			}
		})
	}
}

func TestAuthorizedProbesBlockedBaselineStopsBeforePayloads(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(http.StatusTooManyRequests) }))
	defer server.Close()
	events, err := probeAuthorizedCandidate(server.Client(), DiscoveryCandidate{URL: server.URL + "?cat=1", ParameterName: "cat", OriginalValue: "1"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") || len(events) != 0 || requests != 1 {
		t.Fatalf("blocked baseline must stop before payloads: requests=%d events=%+v err=%v", requests, events, err)
	}
}

type externalTestTransport func(*http.Request) (*http.Response, error)

func (f externalTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthorizedTimeoutEmitsFailedRequestWithoutVerdict(t *testing.T) {
	client := &http.Client{Transport: externalTestTransport(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded })}
	var activity []models.LabActivityEvent
	events, err := probeAuthorizedCandidateWithTrace(client, DiscoveryCandidate{URL: "http://testphp.vulnweb.com/listproducts.php?cat=1", ParameterName: "cat", OriginalValue: "1"}, "candidate-1", 0, 7, func(event models.LabActivityEvent) { activity = append(activity, event) })
	if err == nil || !strings.Contains(err.Error(), "tiempo limite") || len(events) != 0 || len(activity) != 2 {
		t.Fatalf("events=%+v activity=%+v err=%v", events, activity, err)
	}
	failed := activity[1]
	if failed.State != "failed" || failed.StatusCode != nil || failed.DurationMS == nil || failed.RequestTotal != 7 || failed.Parameter != "cat" {
		t.Fatalf("fabricated or missing timeout metadata: %+v", failed)
	}
}

func TestAuthorizedTraceAndPartialEvidence(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("cat") == "1'" {
			_, _ = w.Write([]byte("You have an error in your SQL syntax"))
			return
		}
		_, _ = w.Write([]byte("catalog"))
	}))
	defer server.Close()
	client := server.Client()
	transport, attempts := client.Transport, 0
	client.Transport = externalTestTransport(func(request *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 4 {
			return nil, context.DeadlineExceeded
		}
		return transport.RoundTrip(request)
	})
	var activity []models.LabActivityEvent
	events, err := probeAuthorizedCandidateWithTrace(client, DiscoveryCandidate{URL: server.URL + "?cat=1", ParameterName: "cat", OriginalValue: "1"}, "candidate-2", 7, 14, func(event models.LabActivityEvent) { activity = append(activity, event) })
	if err == nil || len(events) != 1 || events[0].Result != "DETECTED" || events[0].Method != "GET" || events[0].ObservedDurationMS == nil {
		t.Fatalf("lost completed evidence: %+v err=%v", events, err)
	}
	if len(activity) != 8 || activity[7].State != "failed" || activity[1].RequestNumber != 8 || activity[1].StatusCode == nil || activity[1].ResponseBytes == nil {
		t.Fatalf("invalid trace: %+v", activity)
	}
}

func TestDiscoveryInitialFailureIsNotAnEmptySuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	var activity []models.LabActivityEvent
	candidates, summary, err := discoverCandidates(server.Client(), server.URL, func(event models.LabActivityEvent) { activity = append(activity, event) })
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") || len(candidates) != 0 || summary.PagesVisited != 0 || len(activity) != 2 || activity[1].State != "http_error" {
		t.Fatalf("candidates=%+v summary=%+v activity=%+v err=%v", candidates, summary, activity, err)
	}
}

func TestDiscoveryStaysOnOriginAndLimitsPages(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/html")
		for i := 0; i < 12; i++ {
			_, _ = fmt.Fprintf(w, `<a href="/page%d?cat=1">item</a>`, i)
		}
	}))
	defer server.Close()
	candidates, summary, err := discoverCandidates(server.Client(), server.URL, nil)
	if err != nil || len(candidates) != 12 || summary.PagesVisited != 5 || requests != 5 {
		t.Fatalf("candidates=%d summary=%+v requests=%d err=%v", len(candidates), summary, requests, err)
	}
	base, _ := http.NewRequest("GET", "http://testphp.vulnweb.com/", nil)
	for _, reference := range []string{"https://testphp.vulnweb.com/?cat=1", "http://testphp.vulnweb.com:8080/?cat=1", "http://user:pass@testphp.vulnweb.com/?cat=1", "http://example.com/?cat=1"} {
		if _, allowed := resolveDiscoveredLink(base.URL, reference, base.URL.Hostname()); allowed {
			t.Fatalf("out-of-origin link accepted: %s", reference)
		}
	}
}

func TestAuthorizedOversizedResponseCannotProduceBooleanVerdict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", responseLimit+1)))
	}))
	defer server.Close()
	events, err := probeAuthorizedCandidate(server.Client(), DiscoveryCandidate{URL: server.URL + "?cat=1", ParameterName: "cat", OriginalValue: "1"})
	if err == nil || len(events) != 0 {
		t.Fatalf("truncated body produced verdict: %+v err=%v", events, err)
	}
}

func TestAuthorizedProbesDynamicResponsesAreInconclusive(t *testing.T) {
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		_, _ = w.Write([]byte(strings.Repeat("dynamic", count)))
	}))
	defer server.Close()
	events, err := probeAuthorizedCandidate(server.Client(), DiscoveryCandidate{URL: server.URL + "?cat=1", ParameterName: "cat", OriginalValue: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if events[1].Result != "INCONCLUSIVE" {
		t.Fatalf("dynamic page produced a verdict: %+v", events[1])
	}
}

func TestAuthorizedClientAcceptsSelectedHostAndRejectsOtherOrigins(t *testing.T) {
	if _, err := authorizedClient("http://example.com/?cat=1"); err != nil {
		t.Fatal("selected host rejected")
	}
	client, err := authorizedClient("http://testphp.vulnweb.com/?cat=1")
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{"http://example.com/", "http://testphp.vulnweb.com:8080/", "http://testphp.vulnweb.com.evil.example/"} {
		req, _ := http.NewRequest(http.MethodGet, destination, nil)
		if client.CheckRedirect(req, nil) == nil {
			t.Fatalf("redirect accepted: %s", destination)
		}
	}
}

func TestCustomPortBasicAuthHTTPRequestsDoNotExposeCredentialsInEvidence(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		user, password, ok := r.BasicAuth()
		if !ok || user != "workshop-user" || password != "private-test-secret" || r.URL.User != nil {
			t.Error("basic authentication missing or leaked into request URL")
		}
		_, _ = w.Write([]byte("stable catalog"))
	}))
	defer server.Close()
	client, err := authorizedClient(server.URL, url.UserPassword("workshop-user", "private-test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	var activity []models.LabActivityEvent
	events, err := probeAuthorizedCandidateWithTrace(client, DiscoveryCandidate{URL: server.URL + "?cat=1", ParameterName: "cat", OriginalValue: "1"}, "candidate-1", 0, 7, func(event models.LabActivityEvent) { activity = append(activity, event) })
	if err != nil || requests != 7 || len(events) != 2 {
		t.Fatalf("requests=%d events=%d err=%v", requests, len(events), err)
	}
	for _, value := range []any{activity, events} {
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), "workshop-user") || strings.Contains(string(encoded), "private-test-secret") || strings.Contains(string(encoded), "Authorization") {
			t.Fatal("credentials leaked into evidence")
		}
	}
}

func TestAuthorizedClientCredentialsStayOnSelectedPort(t *testing.T) {
	client, err := authorizedClient("http://workshop-user:secret@testphp.vulnweb.com:8080/?cat=1")
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*authorizedTransport)
	if transport.origin.User != nil || transport.origin.Port() != "8080" || transport.credentials == nil {
		t.Fatal("client lost sanitized origin or credentials")
	}
	called := false
	transport.base = externalTestTransport(func(req *http.Request) (*http.Response, error) { called = true; return nil, context.DeadlineExceeded })
	outside, _ := http.NewRequest("GET", "http://testphp.vulnweb.com:8000/", nil)
	if _, err := transport.RoundTrip(outside); err == nil || called {
		t.Fatal("credentials sent to a different port")
	}
	redirect, _ := http.NewRequest("GET", "http://injected:secret@testphp.vulnweb.com:8080/", nil)
	if err := client.CheckRedirect(redirect, nil); err == nil || redirect.URL.User != nil {
		t.Fatal("redirect credentials were not rejected and redacted")
	}
}
