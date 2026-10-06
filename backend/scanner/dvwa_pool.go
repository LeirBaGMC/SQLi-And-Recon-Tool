package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/models"
)

type dvwaProbe struct {
	value, summary string
	response       requestResult
	err            error
	worker         int
}

func dvwaProbeTarget(targetURL, level, value string) (string, url.Values, error) {
	if level == "medium" || level == "high" {
		parsed, err := url.Parse(targetURL)
		if err != nil {
			return "", nil, err
		}
		parsed.RawQuery = ""
		return parsed.String(), url.Values{"id": {value}, "Submit": {"Submit"}}, nil
	}
	endpoint, err := replaceQueryValue(targetURL, "id", value)
	return endpoint, nil, err
}

// High stores id in PHP's session. A worker owns its cookie jar and finishes
// the POST + GET pair before taking another job; sessions are never shared.
func executeDVWAProbe(client *http.Client, targetURL, level string, number, worker int, probe dvwaProbe, observe dvwaObserver) dvwaProbe {
	probe.worker = worker
	endpoint, values, err := dvwaProbeTarget(targetURL, level, probe.value)
	if err != nil {
		probe.err = err
		return probe
	}
	step := models.LabActivityEvent{StepID: fmt.Sprintf("probe-%d", number), Stage: "probe", Level: level, Summary: probe.summary, Payload: probe.value, RequestNumber: number, RequestTotal: 6, WorkerID: worker}
	if level == "high" {
		parsed, _ := url.Parse(endpoint)
		inputURL := parsed.ResolveReference(&url.URL{Path: "session-input.php"}).String()
		input := step
		input.StepID, input.Stage, input.Summary = fmt.Sprintf("input-%d", number), "input", "Guardar id en la sesión · "+probe.summary
		input.RequestNumber, input.RequestTotal = 0, 0
		stored, err := dvwaRequest(client, inputURL, values, input, observe)
		if err != nil {
			probe.err = err
			return probe
		}
		if stored.StatusCode != http.StatusOK || strings.Contains(stored.FinalURL, "login.php") || strings.Contains(stored.FinalURL, "setup.php") {
			probe.err = fmt.Errorf("DVWA High no acepto la entrada de sesion (HTTP %d)", stored.StatusCode)
			return probe
		}
		values = nil
	}
	probe.response, probe.err = dvwaRequest(client, endpoint, values, step, observe)
	if probe.err != nil {
		return probe
	}
	response := probe.response
	if strings.Contains(response.FinalURL, "login.php") || strings.Contains(response.FinalURL, "setup.php") {
		probe.err = fmt.Errorf("la sesion DVWA expiro o falta inicializar su base de datos")
	} else if number != 2 && (sqlErrorSignature(response.Body) != "" || (level == "high" && strings.Contains(response.Body, "Something went wrong."))) {
		probe.err = fmt.Errorf("DVWA devolvio un error en una sonda de control; no equivale a cero registros")
	} else if response.StatusCode != http.StatusOK && !(number == 2 && response.StatusCode == 500 && sqlErrorSignature(response.Body) != "") {
		probe.err = fmt.Errorf("DVWA respondio HTTP %d en sonda %d", response.StatusCode, number)
	}
	return probe
}

func probeDVWA(client *http.Client, targetURL, level string, observe dvwaObserver) ([]models.PayloadExecutionEvent, error) {
	return probeDVWAConcurrent([]*http.Client{client}, targetURL, level, observe)
}

func probeDVWAConcurrent(clients []*http.Client, targetURL, level string, observe dvwaObserver) ([]models.PayloadExecutionEvent, error) {
	if level != "low" && level != "medium" && level != "high" {
		return nil, fmt.Errorf("nivel DVWA no compatible")
	}
	if len(clients) != 1 && len(clients) != 2 && len(clients) != 4 {
		return nil, fmt.Errorf("numero de workers DVWA no compatible")
	}
	trueValue, falseValue := "1' AND '1'='1", "1' AND '1'='2"
	if level == "medium" {
		trueValue, falseValue = "1 AND 1=1", "1 AND 1=2"
	}
	probes := []dvwaProbe{
		{value: "1", summary: "Establecer línea base · id=1"},
		{value: "1'", summary: "Probar error SQL · comilla en id"},
		{value: trueValue, summary: "Condición verdadera · repetición 1/2"},
		{value: falseValue, summary: "Condición falsa · repetición 1/2"},
		{value: trueValue, summary: "Condición verdadera · repetición 2/2"},
		{value: falseValue, summary: "Condición falsa · repetición 2/2"},
	}
	// Serialize observer callbacks so logging consumers need not be thread safe.
	var observeMu sync.Mutex
	serialObserve := func(event models.LabActivityEvent) {
		observeMu.Lock()
		defer observeMu.Unlock()
		observeDVWA(observe, event)
	}
	probes[0] = executeDVWAProbe(clients[0], targetURL, level, 1, 1, probes[0], serialObserve)
	baseline := probes[0].response
	if probes[0].err != nil {
		return nil, probes[0].err
	}
	baseRows := dvwaRows(baseline.Body)
	if len(baseRows) == 0 {
		return nil, fmt.Errorf("DVWA no devolvio registros base; verifica el modulo SQL Injection y nivel %s", level)
	}
	serialObserve(models.LabActivityEvent{StepID: "baseline-verified", Stage: "validation", State: "completed", Level: level, Summary: fmt.Sprintf("Línea base verificada · %d registro(s)", len(baseRows))})
	jobs := make(chan int, len(probes)-1)
	for index := 1; index < len(probes); index++ {
		jobs <- index
	}
	close(jobs)
	var wg sync.WaitGroup
	for worker, client := range clients {
		wg.Add(1)
		go func(worker int, client *http.Client) {
			defer wg.Done()
			for index := range jobs {
				probes[index] = executeDVWAProbe(client, targetURL, level, index+1, worker+1, probes[index], serialObserve)
			}
		}(worker, client)
	}
	wg.Wait()
	// Evaluate fixed logical slots, never completion order. Failed jobs are
	// retained as inconclusive; other jobs finish and keep their evidence.
	method := http.MethodGet
	if level == "medium" {
		method = http.MethodPost
	}
	makeEvent := func(name, payload string, observed dvwaProbe, indexes []int) models.PayloadExecutionEvent {
		endpoint, values, _ := dvwaProbeTarget(targetURL, level, observed.value)
		event := models.PayloadExecutionEvent{Name: name, Parameter: "id", Payload: payload, TestedURL: endpoint, StatusCode: observed.response.StatusCode, BaselineSize: len(baseline.Body), ObservedSize: len(observed.response.Body), Result: "NOT_DETECTED", Risk: "LOW", ExecutionType: "REAL", Method: method, DVWALevel: level, BaselineDurationMS: &baseline.DurationMS}
		if observed.err == nil {
			event.ObservedDurationMS = &observed.response.DurationMS
		}
		if values != nil {
			event.RequestBody = values.Encode()
		}
		if level == "high" {
			parsed, _ := url.Parse(endpoint)
			event.InputURL = parsed.ResolveReference(&url.URL{Path: "session-input.php"}).String()
			event.CoverageNote = "High: POST de id a session-input.php seguido de GET al modulo, en la misma sesión del worker. LIMIT 1 y ocultar errores no corrigen la inyección; la firma de error se evalúa según la respuesta real."
		}
		for _, index := range indexes {
			probe := probes[index]
			value := fmt.Sprintf("worker %d · HTTP %d · %d ms · %d registros", probe.worker, probe.response.StatusCode, probe.response.DurationMS, len(dvwaRows(probe.response.Body)))
			if probe.err != nil {
				value = "INCONCLUSIVE: " + probe.err.Error()
			}
			event.Checks = append(event.Checks, models.ProbeCheck{Label: probe.summary, Value: value})
		}
		return event
	}
	errorEvent := makeEvent("DVWA · Error SQL", "1'", probes[1], []int{0, 1})
	errorEvent.Reason, errorEvent.Remediation = "No se observo una firma nueva de error SQL.", "Usar consultas preparadas y ocultar errores SQL en respuestas HTTP."
	if probes[1].err != nil {
		errorEvent.Result, errorEvent.Reason = "INCONCLUSIVE", probes[1].err.Error()
	} else if signature := sqlErrorSignature(probes[1].response.Body); signature != "" && sqlErrorSignature(baseline.Body) == "" {
		errorEvent.Result, errorEvent.Risk, errorEvent.Reason = "DETECTED", "HIGH", "La entrada con comilla introdujo un error SQL: "+signature
	}
	boolean := makeEvent("DVWA · Comparacion booleana", trueValue+" / "+falseValue, probes[3], []int{0, 2, 3, 4, 5})
	boolean.Reason, boolean.Remediation = "Las condiciones no reprodujeron una diferencia booleana en los registros devueltos.", "Separar id de la estructura SQL usando una consulta parametrizada."
	var probeErrors []error
	for index := 1; index < len(probes); index++ {
		if probes[index].err != nil {
			probeErrors = append(probeErrors, probes[index].err)
			if index >= 2 {
				boolean.Result, boolean.Reason = "INCONCLUSIVE", "No se completaron los dos pares booleanos; consulta la evidencia de cada sonda."
			}
		}
	}
	if boolean.Result != "INCONCLUSIVE" {
		trueRows, falseRows := dvwaRows(probes[2].response.Body), dvwaRows(probes[3].response.Body)
		baseCount, trueCount, falseCount := len(baseRows), len(trueRows), len(falseRows)
		boolean.BaselineRecords, boolean.TrueRecords, boolean.ObservedRecords = &baseCount, &trueCount, &falseCount
		if strings.Join(trueRows, "\n") != strings.Join(dvwaRows(probes[4].response.Body), "\n") || strings.Join(falseRows, "\n") != strings.Join(dvwaRows(probes[5].response.Body), "\n") {
			boolean.Result, boolean.Reason = "INCONCLUSIVE", "Los registros variaron entre repeticiones; no hay evidencia booleana reproducible."
		} else if strings.Join(baseRows, "\n") == strings.Join(trueRows, "\n") && len(falseRows) == 0 {
			boolean.Result, boolean.Risk, boolean.Reason = "DETECTED", "HIGH", fmt.Sprintf("Dos repeticiones confirmaron %d registros con condicion verdadera y 0 con condicion falsa; evidencia HTTP de alteracion del filtro SQL.", len(trueRows))
		}
	}
	return []models.PayloadExecutionEvent{errorEvent, boolean}, errors.Join(probeErrors...)
}

func runDVWAScan(scanID, targetURL, level string, workers int, repo *database.Repository) (scanErr error) {
	if workers == 0 {
		workers = 1
	}
	if workers != 1 && workers != 2 && workers != 4 {
		return fmt.Errorf("numero de workers DVWA no compatible")
	}
	started := time.Now()
	metrics := models.DVWAMetrics{Level: level, Workers: workers}
	defer func() {
		metrics.TotalMS = float64(time.Since(started).Microseconds()) / 1000
		message, _ := json.Marshal(metrics)
		if err := repo.CreateScanEvent(scanID, "DVWA_METRICS", string(message)); err != nil {
			scanErr = errors.Join(scanErr, fmt.Errorf("no se pudo conservar la medicion DVWA: %w", err))
		}
	}()
	origin, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	baseURL := origin.Scheme + "://" + origin.Host
	username, password := os.Getenv("DVWA_USERNAME"), os.Getenv("DVWA_PASSWORD")
	if username == "" || password == "" {
		return fmt.Errorf("configura DVWA_USERNAME y DVWA_PASSWORD en el backend")
	}
	var observeMu sync.Mutex
	trace := newDVWATraceWriter(func(batch []models.LabActivityEvent) error {
		messages := make([]string, 0, len(batch))
		for _, event := range batch {
			message, err := json.Marshal(event)
			if err != nil {
				return err
			}
			messages = append(messages, string(message))
		}
		return repo.CreateScanEvents(scanID, "LAB_ACTIVITY", messages)
	})
	defer func() {
		flushStarted := time.Now()
		if err := trace.Close(); err != nil {
			scanErr = errors.Join(scanErr, fmt.Errorf("no se pudo conservar la evidencia HTTP de DVWA: %w", err))
		}
		metrics.EvidenceMS += float64(time.Since(flushStarted).Microseconds()) / 1000
	}()
	observe := func(event models.LabActivityEvent) {
		observeMu.Lock()
		defer observeMu.Unlock()
		if event.Method != "" && event.State != "running" {
			metrics.HTTPRequests++
			if event.State == "failed" {
				metrics.FailedRequests++
			}
			if event.State == "http_error" {
				metrics.HTTPErrorResponses++
			}
			if event.Stage == "probe" && event.State != "failed" {
				metrics.CompletedProbes++
			}
		}
		trace.Observe(event)
	}
	clients := make([]*http.Client, workers)
	loginErrors := make([]error, workers)
	var wg sync.WaitGroup
	sessionStarted := time.Now()
	for worker := range clients {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			client, err := newDVWAClient(baseURL)
			if err != nil {
				loginErrors[worker] = err
				return
			}
			clients[worker] = client
			loginErrors[worker] = loginDVWA(client, baseURL, username, password, level, func(event models.LabActivityEvent) {
				event.StepID = fmt.Sprintf("worker-%d-%s", worker+1, event.StepID)
				event.WorkerID = worker + 1
				observe(event)
			})
		}(worker)
	}
	wg.Wait()
	flushStarted := time.Now()
	sessionTraceErr := trace.Flush()
	metrics.EvidenceMS = float64(time.Since(flushStarted).Microseconds()) / 1000
	metrics.SessionMS = float64(time.Since(sessionStarted).Microseconds()) / 1000
	if sessionTraceErr != nil {
		sessionTraceErr = fmt.Errorf("no se pudo conservar la evidencia HTTP de DVWA: %w", sessionTraceErr)
	}
	if err := errors.Join(append(loginErrors, sessionTraceErr)...); err != nil {
		return err
	}
	repo.CreateEventWithoutInterrupting(scanID, "SESSION_AUTHENTICATED", fmt.Sprintf("%d sesiones DVWA independientes; nivel %s confirmado.", workers, level))
	probeStarted := time.Now()
	events, probeErr := probeDVWAConcurrent(clients, targetURL, level, observe)
	metrics.ProbeMS = float64(time.Since(probeStarted).Microseconds()) / 1000
	flushStarted = time.Now()
	traceErr := trace.Close()
	metrics.EvidenceMS += float64(time.Since(flushStarted).Microseconds()) / 1000
	if traceErr != nil {
		traceErr = fmt.Errorf("no se pudo conservar la evidencia HTTP de DVWA: %w", traceErr)
	}
	for _, event := range events {
		if event.Result == "DETECTED" {
			metrics.Detected++
		}
		if event.Result == "INCONCLUSIVE" {
			metrics.Inconclusive++
		}
	}
	if err := saveHTTPProbeEvents(scanID, events, repo); err != nil {
		return err
	}
	return errors.Join(probeErr, traceErr)
}
