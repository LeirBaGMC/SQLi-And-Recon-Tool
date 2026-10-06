package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeirBaGMC/sql-scanner/models"
)

func TestDVWAPoolIsolatesHighSessionAndPreservesEvidence(t *testing.T) {
	for _, workers := range []int{1, 2, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			var mu sync.Mutex
			sessions := map[string]string{}
			pending := map[string]bool{}
			active, peak, posts, gets := 0, 0, 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie, err := r.Cookie("PHPSESSID")
				if err != nil {
					t.Error("missing session")
					w.WriteHeader(403)
					return
				}
				mu.Lock()
				if r.URL.Path == "/vulnerabilities/sqli/session-input.php" {
					if r.Method != "POST" {
						t.Error("High input must be POST")
					}
					if pending[cookie.Value] {
						t.Error("another payload overwrote a pending session input")
					}
					sessions[cookie.Value], pending[cookie.Value] = r.FormValue("id"), true
					posts++
					mu.Unlock()
					fmt.Fprint(w, "Session ID set")
					return
				}
				if r.Method != "GET" || r.URL.RawQuery != "" || !pending[cookie.Value] {
					t.Error("High GET did not follow its own POST")
				}
				id := sessions[cookie.Value]
				pending[cookie.Value] = false
				gets++
				active++
				if active > peak {
					peak = active
				}
				mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				switch id {
				case "1'":
					fmt.Fprint(w, "<pre>Something went wrong.</pre>")
				case "1' AND '1'='2":
					fmt.Fprint(w, "No rows")
				case "1", "1' AND '1'='1":
					fmt.Fprintf(w, "<pre>ID: %s<br>First name: a<br>Surname: b</pre>", id)
				default:
					t.Errorf("unexpected id %q", id)
				}
				mu.Lock()
				active--
				mu.Unlock()
			}))
			defer server.Close()
			clients := make([]*http.Client, workers)
			origin, _ := url.Parse(server.URL)
			for worker := range clients {
				clients[worker], _ = newDVWAClient(server.URL)
				clients[worker].Jar.SetCookies(origin, []*http.Cookie{{Name: "PHPSESSID", Value: fmt.Sprintf("session-%d", worker), Path: "/"}})
			}
			trace := []models.LabActivityEvent{}
			events, err := probeDVWAConcurrent(clients, server.URL+"/vulnerabilities/sqli/", "high", func(event models.LabActivityEvent) { trace = append(trace, event) })
			if err != nil {
				t.Fatal(err)
			}
			if posts != 6 || gets != 6 || len(sessions) != workers || peak > workers || (workers > 1 && peak < 2) {
				t.Fatalf("unbounded or inactive pool: posts=%d gets=%d sessions=%d peak=%d", posts, gets, len(sessions), peak)
			}
			if len(events) != 2 || events[0].Result != "NOT_DETECTED" || events[1].Result != "DETECTED" || *events[1].ObservedRecords != 0 || *events[1].TrueRecords != 1 || len(events[1].Checks) != 5 || !strings.HasSuffix(events[1].InputURL, "/session-input.php") {
				t.Fatalf("lost High evidence: %+v", events)
			}
			seen := map[string]bool{}
			for _, event := range trace {
				if event.State == "completed" && (event.Stage == "input" || event.Stage == "probe") {
					if seen[event.StepID] {
						t.Fatalf("duplicate request ID: %s", event.StepID)
					}
					seen[event.StepID] = true
					if event.WorkerID < 1 || event.WorkerID > workers {
						t.Fatal("missing worker attribution")
					}
				}
			}
			if len(seen) != 12 {
				t.Fatalf("lost transport trace: %d", len(seen))
			}
		})
	}
}

func TestDVWAPoolDoesNotTurnNegativeOrUnstableResponsesIntoFindings(t *testing.T) {
	for _, scenario := range []string{"parametrized", "unstable", "masked-error"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			trueCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				id := r.URL.Query().Get("id")
				if id == "1" {
					fmt.Fprint(w, "<pre>First name: a<br>Surname: b</pre>")
					return
				}
				if scenario == "parametrized" {
					fmt.Fprint(w, "No matching ID")
					return
				}
				if strings.HasSuffix(id, "='1") {
					trueCount++
					name := "a"
					if scenario == "unstable" && trueCount == 2 {
						name = "changed"
					}
					fmt.Fprintf(w, "<pre>First name: %s<br>Surname: b</pre>", name)
				} else if scenario == "masked-error" {
					fmt.Fprint(w, "You have an error in your SQL syntax")
				} else {
					fmt.Fprint(w, "No rows")
				}
			}))
			defer server.Close()
			clients := make([]*http.Client, 4)
			for i := range clients {
				clients[i], _ = newDVWAClient(server.URL)
			}
			events, err := probeDVWAConcurrent(clients, server.URL+"/?id=1", "low", nil)
			if len(events) != 2 {
				t.Fatalf("missing evidence: %v", events)
			}
			want := "INCONCLUSIVE"
			if scenario == "parametrized" {
				want = "NOT_DETECTED"
			}
			if events[1].Result != want {
				t.Fatalf("false boolean finding: %+v", events[1])
			}
			if scenario == "masked-error" && err == nil {
				t.Fatal("SQL error in a control was accepted as empty rows")
			}
		})
	}
}

func TestDVWAHighInputFailureNeverUsesStaleSession(t *testing.T) {
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(403)
			return
		}
		gets++
		fmt.Fprint(w, "<pre>First name: stale<br>Surname: stale</pre>")
	}))
	defer server.Close()
	client, _ := newDVWAClient(server.URL)
	events, err := probeDVWA(client, server.URL+"/vulnerabilities/sqli/", "high", nil)
	if err == nil || gets != 0 || len(events) != 0 {
		t.Fatal("failed input reused previous session evidence")
	}
}
