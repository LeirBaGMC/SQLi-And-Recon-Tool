package scanner

import (
	"errors"
	"fmt"
	"github.com/LeirBaGMC/sql-scanner/models"
	"testing"
)

func TestDVWATraceBatchesRetainEveryEventInOrderAndDrainBeforeCompletion(t *testing.T) {
	var saved []string
	commits := 0
	w := newDVWATraceWriter(func(events []models.LabActivityEvent) error {
		commits++
		if len(events) > 16 {
			t.Error("unbounded batch")
		}
		for _, event := range events {
			saved = append(saved, event.StepID)
		}
		return nil
	})
	for i := 0; i < 75; i++ {
		w.Observe(models.LabActivityEvent{StepID: fmt.Sprint(i)})
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 75 {
		t.Fatalf("flush lost events: %d", len(saved))
	}
	w.Observe(models.LabActivityEvent{StepID: "final"})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 76 || saved[75] != "final" || commits >= 76 {
		t.Fatal("did not drain and batch evidence")
	}
	for i := 0; i < 75; i++ {
		if saved[i] != fmt.Sprint(i) {
			t.Fatal("reordered events")
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDVWATracePersistenceErrorDrainsProducersButFailsCompletion(t *testing.T) {
	failure := errors.New("commit failed")
	w := newDVWATraceWriter(func([]models.LabActivityEvent) error { return failure })
	for i := 0; i < 200; i++ {
		w.Observe(models.LabActivityEvent{StepID: fmt.Sprint(i)})
	}
	if !errors.Is(w.Flush(), failure) || !errors.Is(w.Close(), failure) {
		t.Fatal("lost persistence failure")
	}
}
