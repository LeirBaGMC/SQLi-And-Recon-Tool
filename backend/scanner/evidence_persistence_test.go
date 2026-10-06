package scanner

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/models"
	"github.com/LeirBaGMC/sql-scanner/policy"
)

type failingEvidenceDriver struct{}
type failingEvidenceConn struct{}
type failingEvidenceStmt struct{}

func (failingEvidenceDriver) Open(string) (driver.Conn, error)  { return failingEvidenceConn{}, nil }
func (failingEvidenceConn) Prepare(string) (driver.Stmt, error) { return failingEvidenceStmt{}, nil }
func (failingEvidenceConn) Close() error                        { return nil }
func (failingEvidenceConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }
func (failingEvidenceStmt) Close() error                        { return nil }
func (failingEvidenceStmt) NumInput() int                       { return -1 }
func (failingEvidenceStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("evidence storage unavailable")
}
func (failingEvidenceStmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, errors.New("not supported")
}

func init() {
	sql.Register("failing-dvwa-evidence", failingEvidenceDriver{})
	sql.Register("selective-http-evidence", selectiveEvidenceDriver{})
}

type selectiveEvidenceState struct {
	fail                        func(models.LabActivityEvent) bool
	status, errorMessage        string
	lost, savedProbes, findings int
}

var selectiveEvidenceStates sync.Map

type selectiveEvidenceDriver struct{}
type selectiveEvidenceConn struct{ state *selectiveEvidenceState }

func (selectiveEvidenceDriver) Open(name string) (driver.Conn, error) {
	state, ok := selectiveEvidenceStates.Load(name)
	if !ok {
		return nil, fmt.Errorf("unknown test database")
	}
	return selectiveEvidenceConn{state.(*selectiveEvidenceState)}, nil
}
func (selectiveEvidenceConn) Close() error                        { return nil }
func (selectiveEvidenceConn) Prepare(string) (driver.Stmt, error) { return nil, fmt.Errorf("unused") }
func (selectiveEvidenceConn) Begin() (driver.Tx, error)           { return nil, fmt.Errorf("unused") }
func (c selectiveEvidenceConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "UPDATE scans") {
		c.state.status = args[0].Value.(string)
		if c.state.status == "FAILED" {
			c.state.errorMessage = args[1].Value.(string)
		}
	}
	if strings.Contains(query, "INSERT INTO findings") {
		c.state.findings++
	}
	if strings.Contains(query, "INSERT INTO scan_events") {
		switch args[1].Value {
		case "HTTP_ACTIVITY":
			var activity models.LabActivityEvent
			if err := json.Unmarshal([]byte(args[2].Value.(string)), &activity); err != nil {
				return nil, err
			}
			if c.state.fail(activity) {
				c.state.lost++
				return nil, fmt.Errorf("HTTP trace storage unavailable")
			}
		case "PAYLOAD_EXECUTED":
			c.state.savedProbes++
		}
	}
	return driver.RowsAffected(1), nil
}

func TestAuthorizedEvidenceLossFailsScanAndRetainsEarlierFindings(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		parameterized              bool
		fail                       func(models.LabActivityEvent) bool
		requests, probes, findings int
	}{
		{"probe-start", true, func(e models.LabActivityEvent) bool { return e.State == "running" }, 0, 0, 0},
		{"probe-response", true, func(e models.LabActivityEvent) bool { return e.State == "completed" }, 1, 0, 0},
		{"after-detection", true, func(e models.LabActivityEvent) bool { return e.RequestNumber == 4 && e.State == "running" }, 3, 1, 1},
		{"nested-discovery", false, func(e models.LabActivityEvent) bool { return e.StepID == "discovery-2" && e.State == "completed" }, 2, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "text/html")
				if !tc.parameterized {
					fmt.Fprint(w, `<a href="/item">Item</a>`)
					return
				}
				if r.URL.Query().Get("id") == "1'" {
					fmt.Fprint(w, "You have an error in your SQL syntax")
					return
				}
				fmt.Fprint(w, "stable catalog")
			}))
			defer server.Close()
			state := &selectiveEvidenceState{fail: tc.fail}
			selectiveEvidenceStates.Store(t.Name(), state)
			defer selectiveEvidenceStates.Delete(t.Name())
			db, err := sql.Open("selective-http-evidence", t.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			url := server.URL
			if tc.parameterized {
				url += "?id=1"
			}
			target, err := policy.ValidateTarget(policy.TargetRequest{Mode: policy.TargetModeAuthorizedURL, URL: url, AuthorizationConfirmed: true})
			if err != nil {
				t.Fatal(err)
			}
			RunScan("scan", target, database.NewRepository(db))
			if state.status != "FAILED" || !strings.Contains(state.errorMessage, "evidencia HTTP") || state.lost != 1 || state.savedProbes != tc.probes || state.findings != tc.findings || int(requests.Load()) != tc.requests {
				t.Fatalf("lost evidence accepted or previous finding discarded: state=%+v requests=%d", state, requests.Load())
			}
		})
	}
}

func TestEvidencePersistenceFailureCannotCompleteDVWAScan(t *testing.T) {
	db, err := sql.Open("failing-dvwa-evidence", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := database.NewRepository(db)
	if err := saveHTTPProbeEvents("scan", []models.PayloadExecutionEvent{{Result: "DETECTED"}}, repo); err == nil || !strings.Contains(err.Error(), "conservar la evidencia") {
		t.Fatalf("lost probe evidence silently accepted: %v", err)
	}
	t.Setenv("DVWA_USERNAME", "training")
	t.Setenv("DVWA_PASSWORD", "training")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.php" {
			fmt.Fprint(w, `<a href="logout.php">Logout</a>`)
			return
		}
		requests++
		if r.Method == "GET" {
			fmt.Fprint(w, `<input name="user_token" value="test-token">`)
			return
		}
		if r.URL.Path == "/login.php" {
			http.Redirect(w, r, "/index.php", http.StatusFound)
			return
		}
		fmt.Fprint(w, `<em>low</em>`)
	}))
	defer server.Close()
	err = runDVWAScan("scan", server.URL+"/vulnerabilities/sqli/?id=1", "low", 1, repo)
	if err == nil || !strings.Contains(err.Error(), "evidencia HTTP") || !strings.Contains(err.Error(), "medicion DVWA") || requests != 4 {
		t.Fatalf("trace/metrics loss was accepted or probes continued: requests=%d err=%v", requests, err)
	}
}
