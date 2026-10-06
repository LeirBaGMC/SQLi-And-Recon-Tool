package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
)

type recoveryRecord struct {
	status, message string
	completed       bool
}
type recoveryState struct {
	scans     map[string]recoveryRecord
	events    map[string]int
	failEvent bool
}

var recoveryStates sync.Map

type recoveryDriver struct{}
type recoveryConn struct {
	state *recoveryState
	tx    *recoveryTx
}
type recoveryTx struct {
	conn   *recoveryConn
	scans  map[string]recoveryRecord
	events map[string]int
}
type recoveryRows struct{ ids []string }

func init() { sql.Register("scan-recovery-test", recoveryDriver{}) }
func (recoveryDriver) Open(name string) (driver.Conn, error) {
	state, ok := recoveryStates.Load(name)
	if !ok {
		return nil, errors.New("unknown test database")
	}
	return &recoveryConn{state: state.(*recoveryState)}, nil
}
func (*recoveryConn) Close() error                        { return nil }
func (*recoveryConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *recoveryConn) Begin() (driver.Tx, error) {
	tx := &recoveryTx{conn: c, scans: map[string]recoveryRecord{}, events: map[string]int{}}
	for id, record := range c.state.scans {
		tx.scans[id] = record
	}
	for id, count := range c.state.events {
		tx.events[id] = count
	}
	c.tx = tx
	return tx, nil
}
func (c *recoveryConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if c.tx == nil || !strings.Contains(query, "FOR UPDATE") {
		return nil, errors.New("recovery must lock rows in a transaction")
	}
	var ids []string
	for id, record := range c.tx.scans {
		if record.status == "QUEUED" || record.status == "RUNNING" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return &recoveryRows{ids: ids}, nil
}
func (c *recoveryConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.tx == nil {
		return nil, errors.New("recovery write outside transaction")
	}
	switch {
	case strings.HasPrefix(query, "UPDATE scans"):
		id := args[1].Value.(string)
		c.tx.scans[id] = recoveryRecord{status: "FAILED", message: args[0].Value.(string), completed: true}
	case strings.HasPrefix(query, "INSERT INTO scan_events"):
		if c.state.failEvent {
			return nil, errors.New("failure event unavailable")
		}
		if args[1].Value != ScanInterruptedMessage {
			return nil, errors.New("mismatched recovery message")
		}
		c.tx.events[args[0].Value.(string)]++
	default:
		return nil, errors.New("unexpected recovery write")
	}
	return driver.RowsAffected(1), nil
}
func (tx *recoveryTx) Commit() error {
	tx.conn.state.scans, tx.conn.state.events = tx.scans, tx.events
	tx.conn.tx = nil
	return nil
}
func (tx *recoveryTx) Rollback() error  { tx.conn.tx = nil; return nil }
func (*recoveryRows) Columns() []string { return []string{"id"} }
func (*recoveryRows) Close() error      { return nil }
func (r *recoveryRows) Next(values []driver.Value) error {
	if len(r.ids) == 0 {
		return io.EOF
	}
	values[0], r.ids = r.ids[0], r.ids[1:]
	return nil
}

func recoveryRepository(t *testing.T, failEvent bool) (*Repository, *recoveryState) {
	t.Helper()
	state := &recoveryState{scans: map[string]recoveryRecord{
		"queued": {status: "QUEUED"}, "running": {status: "RUNNING"},
		"completed": {status: "COMPLETED", completed: true},
		"failed":    {status: "FAILED", message: "Original failure", completed: true},
	}, events: map[string]int{}, failEvent: failEvent}
	recoveryStates.Store(t.Name(), state)
	db, err := sql.Open("scan-recovery-test", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); recoveryStates.Delete(t.Name()) })
	return NewRepository(db), state
}

func TestRecoveryClosesOnlyUnfinishedScansAndIsIdempotent(t *testing.T) {
	repo, state := recoveryRepository(t, false)
	count, err := repo.FailInterruptedScans(context.Background())
	if err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	for _, id := range []string{"queued", "running"} {
		record := state.scans[id]
		if record.status != "FAILED" || record.message != ScanInterruptedMessage || !record.completed || state.events[id] != 1 {
			t.Fatalf("incomplete recovery: %+v", state)
		}
	}
	if state.scans["completed"].status != "COMPLETED" || state.scans["failed"].message != "Original failure" || len(state.events) != 2 {
		t.Fatalf("terminal scans changed: %+v", state)
	}
	count, err = repo.FailInterruptedScans(context.Background())
	if err != nil || count != 0 || state.events["running"] != 1 {
		t.Fatalf("recovery repeated: count=%d state=%+v err=%v", count, state, err)
	}
}

func TestRecoveryRollsBackStatusWhenFailureEvidenceCannotBeSaved(t *testing.T) {
	repo, state := recoveryRepository(t, true)
	count, err := repo.FailInterruptedScans(context.Background())
	if err == nil || count != 0 || state.scans["queued"].status != "QUEUED" || state.scans["running"].status != "RUNNING" || len(state.events) != 0 {
		t.Fatalf("partial recovery committed: count=%d state=%+v err=%v", count, state, err)
	}
}
