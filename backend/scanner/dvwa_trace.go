package scanner

import (
	"github.com/LeirBaGMC/sql-scanner/models"
	"sync"
	"time"
)

// One writer commits small batches while probes continue. The bounded channel
// provides backpressure; Close drains it before a scan can report completion.
type dvwaTraceWriter struct {
	events chan dvwaTraceMessage
	done   chan struct{}
	once   sync.Once
	err    error
}

type dvwaTraceMessage struct {
	event *models.LabActivityEvent
	flush chan error
}

func newDVWATraceWriter(save func([]models.LabActivityEvent) error) *dvwaTraceWriter {
	w := &dvwaTraceWriter{events: make(chan dvwaTraceMessage, 64), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		batch := make([]models.LabActivityEvent, 0, 16)
		flush := func() {
			if len(batch) == 0 {
				return
			}
			if w.err == nil {
				w.err = save(batch)
			}
			batch = batch[:0]
		}
		for {
			select {
			case message, open := <-w.events:
				if !open {
					flush()
					return
				}
				if message.flush != nil {
					flush()
					message.flush <- w.err
					continue
				}
				batch = append(batch, *message.event)
				if len(batch) == cap(batch) {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()
	return w
}

func (w *dvwaTraceWriter) Observe(event models.LabActivityEvent) {
	w.events <- dvwaTraceMessage{event: &event}
}
func (w *dvwaTraceWriter) Flush() error {
	result := make(chan error, 1)
	w.events <- dvwaTraceMessage{flush: result}
	return <-result
}
func (w *dvwaTraceWriter) Close() error {
	w.once.Do(func() { close(w.events) })
	<-w.done
	return w.err
}
