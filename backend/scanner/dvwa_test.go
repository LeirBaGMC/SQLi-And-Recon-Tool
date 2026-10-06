package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/LeirBaGMC/sql-scanner/models"
)

func TestDVWATokenAndRows(t *testing.T) {
	token, err := csrfToken(`<input value="a&amp;b" type="hidden" name="user_token">`)
	if err != nil || token != "a&b" {
		t.Fatalf("token parse failed: %q %v", token, err)
	}
	if _, err := csrfToken(`<input name="other" value="x">`); err == nil {
		t.Fatal("missing CSRF token accepted")
	}
	baseline := dvwaRows(`<pre>ID: 1<br />First name: admin<br />Surname: admin</pre>`)
	probe := dvwaRows(`<pre>ID: 1' AND '1'='1<br />First name: admin<br />Surname: admin</pre>`)
	if !reflect.DeepEqual(baseline, probe) || len(baseline) != 1 {
		t.Fatal("reflected input must not change comparison")
	}
	if len(dvwaRows(`<pre>You have an error in your SQL syntax</pre>`)) != 0 {
		t.Fatal("SQL error counted as a user row")
	}
}

func TestDVWAMediumUsesPOSTAndTracesActualResponses(t *testing.T) {
	values := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.FormValue("Submit") != "Submit" {
			t.Error("Medium must send the ID in the POST body")
		}
		id := r.FormValue("id")
		values = append(values, id)
		switch id {
		case "1'":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("You have an error in your SQL syntax"))
		case "1 AND 1=2":
			_, _ = w.Write([]byte("No rows"))
		case "1", "1 AND 1=1":
			_, _ = fmt.Fprintf(w, "<pre>ID: %s<br>First name: private-user<br>Surname: private-surname</pre>", id)
		default:
			t.Errorf("unexpected payload: %q", id)
		}
	}))
	defer server.Close()
	client, _ := newDVWAClient(server.URL)
	trace := []models.LabActivityEvent{}
	probes, err := probeDVWA(client, server.URL+"/vulnerabilities/sqli/", "medium", func(event models.LabActivityEvent) { trace = append(trace, event) })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(values, []string{"1", "1'", "1 AND 1=1", "1 AND 1=2", "1 AND 1=1", "1 AND 1=2"}) {
		t.Fatalf("unexpected request sequence: %v", values)
	}
	if len(probes) != 2 || probes[0].StatusCode != 500 {
		t.Fatalf("missing SQL-error evidence: %+v", probes)
	}
	for _, probe := range probes {
		if probe.Result != "DETECTED" || probe.Method != "POST" || probe.DVWALevel != "medium" || probe.RequestBody == "" || probe.ObservedDurationMS == nil {
			t.Fatalf("incorrect Medium evidence: %+v", probe)
		}
	}
	if *probes[1].BaselineRecords != 1 || *probes[1].TrueRecords != 1 || *probes[1].ObservedRecords != 0 {
		t.Fatal("incorrect Medium row counts")
	}
	completed := 0
	for _, event := range trace {
		if event.Stage == "probe" && event.State != "running" {
			completed++
			if event.StatusCode == nil || event.DurationMS == nil || event.ResponseBytes == nil || event.Records == nil || event.Method != "POST" {
				t.Fatalf("missing response telemetry: %+v", event)
			}
			if event.Payload == "1 AND 1=2" && *event.Records != 0 {
				t.Fatal("empty response reported as a record")
			}
		}
	}
	if completed != 6 {
		t.Fatalf("completed trace requests=%d", completed)
	}
	encoded, _ := json.Marshal(trace)
	if strings.Contains(string(encoded), "private-user") || strings.Contains(string(encoded), "private-surname") {
		t.Fatal("returned user data leaked into activity logs")
	}
}

func TestDVWAMediumLoginTraceDoesNotExposeAuthenticationData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" {
			_, _ = w.Write([]byte(`<a href="logout.php">Logout</a>`))
			return
		}
		if r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "private-session-cookie"})
			_, _ = w.Write([]byte(`<input name="user_token" value="private-csrf-token">`))
			return
		}
		if r.FormValue("user_token") != "private-csrf-token" {
			t.Error("CSRF missing")
		}
		if r.URL.Path == "/login.php" {
			if r.FormValue("password") != "private-login-password" {
				t.Error("login password missing")
			}
			http.Redirect(w, r, "/index.php", http.StatusFound)
		} else {
			if r.FormValue("security") != "medium" {
				t.Error("Medium was not selected")
			}
			_, _ = w.Write([]byte(`<em>medium</em>`))
		}
	}))
	defer server.Close()
	client, _ := newDVWAClient(server.URL)
	trace := []models.LabActivityEvent{}
	if err := loginDVWA(client, server.URL, "admin", "private-login-password", "medium", func(event models.LabActivityEvent) { trace = append(trace, event) }); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(trace)
	for _, secret := range []string{"private-login-password", "private-csrf-token", "private-session-cookie"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("authentication secret leaked into activity logs: %s", secret)
		}
	}
	if len(trace) != 8 {
		t.Fatalf("authentication trace entries=%d", len(trace))
	}
}

func TestDVWAPartialFailureKeepsFinishedProbeAndMarksIncompleteEvidence(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Query().Get("id") {
		case "1":
			_, _ = w.Write([]byte(`<pre>First name: a<br>Surname: b</pre>`))
		case "1'":
			_, _ = w.Write([]byte("You have an error in your SQL syntax"))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	client, _ := newDVWAClient(server.URL)
	probes, err := probeDVWA(client, server.URL+"/vulnerabilities/sqli/?id=1&Submit=Submit", "low", nil)
	if err == nil || requests != 6 || len(probes) != 2 || probes[0].Result != "DETECTED" || probes[1].Result != "INCONCLUSIVE" || probes[1].ObservedRecords != nil {
		t.Fatalf("partial failure lost completed evidence: requests=%d probes=%v err=%v", requests, probes, err)
	}
}

func TestDVWALoginPreservesSessionAndCSRF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login.php":
			if r.Method == http.MethodGet {
				http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "training", Path: "/"})
				_, _ = w.Write([]byte(`<input name="user_token" value="login-token">`))
				return
			}
			cookie, err := r.Cookie("PHPSESSID")
			if err != nil || cookie.Value != "training" || r.FormValue("user_token") != "login-token" || r.FormValue("username") != "admin" || r.FormValue("password") != "password" {
				t.Error("login lost cookies, CSRF or credentials")
			}
			http.Redirect(w, r, "/index.php", http.StatusFound)
		case "/index.php":
			_, _ = w.Write([]byte(`<a href="logout.php">Logout</a>`))
		case "/security.php":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<input value="security-token" name="user_token">`))
				return
			}
			if r.FormValue("user_token") != "security-token" || r.FormValue("security") != "low" {
				t.Error("security form lost CSRF or level")
			}
			_, _ = w.Write([]byte(`<p>Security level is currently: <em>low</em></p>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := newDVWAClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := loginDVWA(client, server.URL, "admin", "password", "low", nil); err != nil {
		t.Fatal(err)
	}
}

func TestDVWALoginFailureStopsScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<input name="user_token" value="token">Login failed`))
	}))
	defer server.Close()
	client, _ := newDVWAClient(server.URL)
	if err := loginDVWA(client, server.URL, "invalid", "invalid", "low", nil); err == nil {
		t.Fatal("failed login accepted")
	}
}

func TestDVWAProbesUseReturnedRowsAndRepeatConditions(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		id := r.URL.Query().Get("id")
		if r.URL.Query().Get("Submit") != "Submit" {
			t.Error("Submit parameter lost")
		}
		switch id {
		case "1'":
			_, _ = w.Write([]byte("You have an error in your SQL syntax"))
		case "1' AND '1'='2":
			_, _ = w.Write([]byte("<html>No rows</html>"))
		default:
			_, _ = fmt.Fprintf(w, "<pre>ID: %s<br>First name: admin<br>Surname: admin</pre><input name='user_token' value='%d'>", id, requests)
		}
	}))
	defer server.Close()
	client, _ := newDVWAClient(server.URL)
	events, err := probeDVWA(client, server.URL+"/vulnerabilities/sqli/?id=1&Submit=Submit", "low", nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 6 || len(events) != 2 {
		t.Fatalf("requests=%d probes=%d", requests, len(events))
	}
	for _, event := range events {
		if event.Result != "DETECTED" || event.ExecutionType != "REAL" {
			t.Fatalf("unexpected event: %+v", event)
		}
	}
	if *events[1].BaselineRecords != 1 || *events[1].TrueRecords != 1 || *events[1].ObservedRecords != 0 {
		t.Fatal("incorrect evidence counts")
	}
}

func TestDVWARedirectsCannotLeaveOrigin(t *testing.T) {
	client, _ := newDVWAClient("http://dvwa")
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/login.php", nil)
	if client.CheckRedirect(req, nil) == nil {
		t.Fatal("out-of-origin redirect accepted")
	}
}
