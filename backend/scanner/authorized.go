package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/models"
	"github.com/LeirBaGMC/sql-scanner/policy"
)

type httpObserver func(models.LabActivityEvent)

func externalRequestError(err error) error {
	var dns *net.DNSError
	var network net.Error
	switch {
	case errors.As(err, &dns):
		return fmt.Errorf("No se pudo resolver el dominio del objetivo. Revisa el DNS y vuelve a intentar")
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		return fmt.Errorf("El objetivo no respondio dentro del tiempo limite. No se pudo completar el analisis; puedes reintentar o usar el laboratorio DVWA")
	default:
		return fmt.Errorf("No se pudo obtener una respuesta valida del objetivo: %w", err)
	}
}

func repositoryHTTPObserver(scanID string, repo *database.Repository) httpObserver {
	return func(event models.LabActivityEvent) {
		message, err := json.Marshal(event)
		if err == nil {
			repo.CreateEventWithoutInterrupting(scanID, "HTTP_ACTIVITY", string(message))
		}
	}
}

func observeHTTP(observe httpObserver, event models.LabActivityEvent) {
	if observe != nil {
		observe(event)
	}
}

// Each request, including redirects, remains on the authorized origin.
func authorizedClient(rawURL string, credentials ...*url.Userinfo) (*http.Client, error) {
	target, err := policy.ValidateTarget(policy.TargetRequest{Mode: policy.TargetModeAuthorizedURL, URL: rawURL, AuthorizationConfirmed: true})
	if err != nil {
		return nil, err
	}
	origin, err := url.Parse(target.URL)
	if err != nil {
		return nil, err
	}
	auth := target.BasicAuth
	if len(credentials) > 0 {
		auth = credentials[0]
	}
	return &http.Client{Timeout: requestTimeout, Transport: &authorizedTransport{base: &pacedTransport{base: http.DefaultTransport}, origin: origin, credentials: auth}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.User != nil {
			req.URL.User = nil
			return fmt.Errorf("redireccion con credenciales no prevista")
		}
		if len(via) >= 5 {
			return fmt.Errorf("limite de redirecciones alcanzado")
		}
		if _, err := policy.ValidateTarget(policy.TargetRequest{Mode: policy.TargetModeAuthorizedURL, URL: req.URL.String(), AuthorizationConfirmed: true}); err != nil {
			return err
		}
		if !strings.EqualFold(req.URL.Host, origin.Host) || req.URL.Scheme != origin.Scheme {
			return fmt.Errorf("redireccion fuera del origen autorizado")
		}
		return nil
	}}, nil
}

// Authentication stays in request headers and is never part of stored URLs.
type authorizedTransport struct {
	base        http.RoundTripper
	origin      *url.URL
	credentials *url.Userinfo
}

func (t *authorizedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != t.origin.Scheme || !strings.EqualFold(req.URL.Host, t.origin.Host) {
		return nil, fmt.Errorf("peticion fuera del origen autorizado")
	}
	copy := req.Clone(req.Context())
	if t.credentials != nil {
		password, _ := t.credentials.Password()
		copy.SetBasicAuth(t.credentials.Username(), password)
	}
	return t.base.RoundTrip(copy)
}

func sqlErrorSignature(body string) string {
	text := strings.ToLower(body)
	for _, signature := range []string{"you have an error in your sql syntax", "unclosed quotation mark after the character string", "quoted string not properly terminated", "mysql_fetch_array()", "mysql_fetch_assoc()", "sqlstate[42000]"} {
		if strings.Contains(text, signature) {
			return signature
		}
	}
	return ""
}

// No writes, extraction or time-delay probes: compare repeated GET responses.
func probeAuthorizedCandidate(client *http.Client, candidate DiscoveryCandidate) ([]models.PayloadExecutionEvent, error) {
	return probeAuthorizedCandidateWithTrace(client, candidate, "candidate-1", 0, authorizedProbeCount(candidate), nil)
}

func authorizedProbeCount(candidate DiscoveryCandidate) int {
	if isNumericValue(candidate.OriginalValue) {
		return 7
	}
	return 3
}

func yesNo(value bool) string {
	if value {
		return "Sí"
	}
	return "No"
}

func responseChecks(baseline, response requestResult) []models.ProbeCheck {
	signature := sqlErrorSignature(response.Body)
	if signature == "" {
		signature = "No encontrada entre los patrones reconocidos"
	}
	return []models.ProbeCheck{
		{Label: "Contenido idéntico a la base", Value: yesNo(response.Body == baseline.Body)},
		{Label: "Diferencia de tamaño", Value: fmt.Sprintf("%+d bytes", len(response.Body)-len(baseline.Body))},
		{Label: "Firma SQL en la respuesta", Value: signature},
	}
}

func probeAuthorizedCandidateWithTrace(client *http.Client, candidate DiscoveryCandidate, prefix string, offset, total int, observe httpObserver) ([]models.PayloadExecutionEvent, error) {
	number := 0
	var reference *requestResult
	request := func(value, summary string) (requestResult, error) {
		rawURL, err := replaceQueryValue(candidate.URL, candidate.ParameterName, value)
		if err != nil {
			return requestResult{}, err
		}
		number++
		step := models.LabActivityEvent{StepID: fmt.Sprintf("%s-probe-%d", prefix, number), Stage: "probe", State: "running", Summary: summary, Method: http.MethodGet, URL: rawURL, Parameter: candidate.ParameterName, Payload: value, RequestNumber: offset + number, RequestTotal: total}
		parsed, _ := url.Parse(rawURL)
		step.OriginalValue, step.EncodedQuery = &candidate.OriginalValue, parsed.RawQuery
		observeHTTP(observe, step)
		started := time.Now()
		result, err := performRequest(client, rawURL)
		if err != nil {
			duration := uint64(time.Since(started).Milliseconds())
			step.State, step.DurationMS, step.Detail = "failed", &duration, err.Error()
			step.Detail += ". No se obtuvo una respuesta completa; no se puede comparar el contenido ni emitir un veredicto con esta petición."
			observeHTTP(observe, step)
			return result, externalRequestError(err)
		}
		step.State = "completed"
		if result.StatusCode >= 400 {
			step.State = "http_error"
		}
		bytes := len(result.Body)
		step.StatusCode, step.DurationMS, step.ResponseBytes = &result.StatusCode, &result.DurationMS, &bytes
		step.FinalURL = result.FinalURL
		if reference != nil {
			step.Checks = responseChecks(*reference, result)
		} else {
			reference = &result
		}
		observeHTTP(observe, step)
		return result, nil
	}
	baseline, err := request(candidate.OriginalValue, "Conectar al objetivo · Linea base")
	if err != nil {
		return nil, fmt.Errorf("peticion base: %w", err)
	}
	if baseline.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("El objetivo devolvio HTTP %d en la linea base. No se enviaron sondas SQL; revisa la URL o reintenta mas tarde", baseline.StatusCode)
	}
	control, err := request(candidate.OriginalValue, "Verificar estabilidad · Repeticion base")
	if err != nil {
		return nil, fmt.Errorf("repeticion base: %w", err)
	}
	if control.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("La repeticion base devolvio HTTP %d. No se enviaron sondas SQL", control.StatusCode)
	}
	stable := baseline.StatusCode == http.StatusOK && control.StatusCode == http.StatusOK && baseline.Body == control.Body
	quoteValue := candidate.OriginalValue + "'"
	quote, err := request(quoteValue, "Comprobar error SQL · "+candidate.ParameterName)
	if err != nil {
		return nil, fmt.Errorf("sonda de error SQL: %w", err)
	}
	quoteURL, _ := replaceQueryValue(candidate.URL, candidate.ParameterName, quoteValue)
	event := models.PayloadExecutionEvent{Name: "Error SQL controlado", Parameter: candidate.ParameterName, Payload: quoteValue, TestedURL: quoteURL, StatusCode: quote.StatusCode, BaselineSize: len(baseline.Body), ObservedSize: len(quote.Body), ExecutionType: "REAL", Result: "NOT_DETECTED", Risk: "LOW", Reason: "No aparecio una firma nueva de error SQL.", Remediation: "Usar consultas parametrizadas y no exponer errores del motor SQL."}
	parsedQuote, _ := url.Parse(quoteURL)
	event.OriginalValue, event.EncodedQuery, event.FinalURL = &candidate.OriginalValue, parsedQuote.RawQuery, quote.FinalURL
	signature := sqlErrorSignature(quote.Body)
	newSignature := signature != "" && !strings.Contains(strings.ToLower(baseline.Body), signature) && !strings.Contains(strings.ToLower(control.Body), signature)
	event.Checks = append(responseChecks(baseline, quote),
		models.ProbeCheck{Label: "Base estable en dos peticiones", Value: yesNo(stable)},
		models.ProbeCheck{Label: "Firma SQL nueva frente a ambas bases", Value: yesNo(newSignature)})
	if quote.Body == baseline.Body {
		event.Reason = "La respuesta al payload fue idéntica a la base y no incluyó una firma nueva de error SQL."
	} else {
		event.Reason = "La respuesta cambió, pero no incluyó una firma nueva de error SQL."
	}
	if baseline.StatusCode != http.StatusOK || control.StatusCode != http.StatusOK || quote.StatusCode == http.StatusForbidden || quote.StatusCode == http.StatusTooManyRequests {
		event.Result, event.Reason = "INCONCLUSIVE", "El objetivo devolvio una respuesta bloqueada o una linea base no valida."
	} else if newSignature {
		event.Result, event.Risk, event.Reason = "DETECTED", "HIGH", "La sonda introdujo una firma de error SQL ausente en ambas respuestas base: "+signature
	} else if quote.StatusCode >= 400 {
		event.Result, event.Reason = "INCONCLUSIVE", "La respuesta de error no permite confirmar ni descartar inyeccion SQL."
	}
	events := []models.PayloadExecutionEvent{event}
	events[0].Method, events[0].BaselineDurationMS, events[0].ObservedDurationMS = http.MethodGet, &baseline.DurationMS, &quote.DurationMS
	// Boolean pairs apply to numeric parameters; text inputs require a different context.
	if !isNumericValue(candidate.OriginalValue) {
		events[0].CoverageNote = "Comparación booleana omitida: el valor original es texto; este motor aplica pares booleanos únicamente a valores numéricos."
		observeHTTP(observe, models.LabActivityEvent{StepID: prefix + "-boolean-skipped", Stage: "coverage", State: "skipped", Summary: "Comparación booleana omitida · " + candidate.ParameterName, Parameter: candidate.ParameterName, OriginalValue: &candidate.OriginalValue, Detail: events[0].CoverageNote})
		return events, nil
	}
	trueValue, falseValue := candidate.OriginalValue+" AND 1=1", candidate.OriginalValue+" AND 1=2"
	trueProbe, err := request(trueValue, "Condicion verdadera · Repeticion 1")
	if err != nil {
		return events, fmt.Errorf("sonda booleana verdadera: %w", err)
	}
	falseProbe, err := request(falseValue, "Condicion falsa · Repeticion 1")
	if err != nil {
		return events, fmt.Errorf("sonda booleana falsa: %w", err)
	}
	trueRepeat, err := request(trueValue, "Condicion verdadera · Repeticion 2")
	if err != nil {
		return events, err
	}
	falseRepeat, err := request(falseValue, "Condicion falsa · Repeticion 2")
	if err != nil {
		return events, err
	}
	falseURL, _ := replaceQueryValue(candidate.URL, candidate.ParameterName, falseValue)
	boolean := models.PayloadExecutionEvent{Name: "Comparacion booleana repetida", Parameter: candidate.ParameterName, Payload: trueValue + " / " + falseValue, TestedURL: falseURL, StatusCode: falseProbe.StatusCode, BaselineSize: len(baseline.Body), ObservedSize: len(falseProbe.Body), ExecutionType: "REAL", Result: "NOT_DETECTED", Risk: "LOW", Reason: "No se observo una diferencia booleana reproducible respecto a la linea base.", Remediation: "Separar los valores de la estructura SQL mediante consultas preparadas."}
	boolean.Method, boolean.BaselineDurationMS, boolean.ObservedDurationMS = http.MethodGet, &baseline.DurationMS, &falseProbe.DurationMS
	parsedFalse, _ := url.Parse(falseURL)
	boolean.OriginalValue, boolean.EncodedQuery, boolean.FinalURL = &candidate.OriginalValue, parsedFalse.RawQuery, falseProbe.FinalURL
	boolean.Checks = []models.ProbeCheck{
		{Label: "Base estable en dos peticiones", Value: yesNo(stable)},
		{Label: "Cuatro respuestas booleanas HTTP 200", Value: yesNo(trueProbe.StatusCode == 200 && falseProbe.StatusCode == 200 && trueRepeat.StatusCode == 200 && falseRepeat.StatusCode == 200)},
		{Label: "Condición verdadera reproducible", Value: yesNo(trueProbe.Body == trueRepeat.Body)},
		{Label: "Condición falsa reproducible", Value: yesNo(falseProbe.Body == falseRepeat.Body)},
		{Label: "Condición verdadera conserva la base", Value: yesNo(trueProbe.Body == baseline.Body)},
		{Label: "Condición falsa cambia la base", Value: yesNo(falseProbe.Body != baseline.Body)},
		{Label: "Payload falso reflejado en la respuesta", Value: yesNo(strings.Contains(falseProbe.Body, falseValue) || strings.Contains(falseProbe.Body, url.QueryEscape(falseValue)))},
	}
	valid := stable && trueProbe.StatusCode == http.StatusOK && falseProbe.StatusCode == http.StatusOK && trueRepeat.StatusCode == http.StatusOK && falseRepeat.StatusCode == http.StatusOK && trueProbe.Body == trueRepeat.Body && falseProbe.Body == falseRepeat.Body
	if !valid {
		boolean.Result, boolean.Reason = "INCONCLUSIVE", "Las respuestas no fueron estables o no devolvieron HTTP 200; no se emite un veredicto booleano."
	} else if trueProbe.Body == baseline.Body && falseProbe.Body != baseline.Body && !strings.Contains(falseProbe.Body, falseValue) && !strings.Contains(falseProbe.Body, url.QueryEscape(falseValue)) {
		boolean.Result, boolean.Risk, boolean.Reason = "DETECTED", "HIGH", "En dos repeticiones, la condicion verdadera mantuvo la respuesta base y la falsa la modifico. Evidencia HTTP; sin confirmacion de kernel."
	}
	return append(events, boolean), nil
}

func isNumericValue(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func executeAuthorizedProbes(scanID string, candidate DiscoveryCandidate, credentials *url.Userinfo, prefix string, offset, total int, repo *database.Repository) error {
	client, err := authorizedClient(candidate.URL, credentials)
	if err != nil {
		return err
	}
	events, probeErr := probeAuthorizedCandidateWithTrace(client, candidate, prefix, offset, total, repositoryHTTPObserver(scanID, repo))
	if err := saveHTTPProbeEvents(scanID, events, repo); err != nil {
		return err
	}
	return probeErr
}

func saveHTTPProbeEvents(scanID string, events []models.PayloadExecutionEvent, repo *database.Repository) error {
	for _, event := range events {
		emitPayloadEvent(repo, scanID, "PAYLOAD_EXECUTED", event)
		if event.Result == "INCONCLUSIVE" {
			repo.CreateEventWithoutInterrupting(scanID, "SCAN_INCONCLUSIVE", event.Reason)
		}
		if event.Result != "DETECTED" {
			continue
		}
		if err := repo.CreateFinding(models.Finding{ScanID: scanID, Category: "SQL_INJECTION_HTTP", Severity: event.Risk, Confidence: "HTTP_ONLY", TestedURL: event.TestedURL, ParameterName: event.Parameter, Payload: event.Payload, Evidence: event.Reason, HTTPStatus: uint16(event.StatusCode)}); err != nil {
			return err
		}
		repo.CreateEventWithoutInterrupting(scanID, "FINDING_CREATED", event.Reason)
	}
	return nil
}

type pacedTransport struct{ base http.RoundTripper }

func (t *pacedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-timer.C:
	}
	return t.base.RoundTrip(req)
}
