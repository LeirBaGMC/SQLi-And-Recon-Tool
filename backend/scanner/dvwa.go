package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/models"
	"golang.org/x/net/html"
)

func csrfToken(body string) (string, error) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return "", err
	}
	var token string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			name, value := "", ""
			for _, a := range n.Attr {
				if a.Key == "name" {
					name = a.Val
				}
				if a.Key == "value" {
					value = a.Val
				}
			}
			if name == "user_token" {
				token = value
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if token == "" {
		return "", fmt.Errorf("DVWA no devolvio el token CSRF esperado")
	}
	return token, nil
}

// Compare returned rows rather than full HTML, which reflects the injected ID.
func dvwaRows(body string) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	rows := []string{}
	var nodeText func(*html.Node) string
	nodeText = func(n *html.Node) string {
		if n.Type == html.TextNode {
			return n.Data
		}
		if n.Type == html.ElementNode && n.Data == "br" {
			return "\n"
		}
		var text strings.Builder
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			text.WriteString(nodeText(child))
		}
		return text.String()
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "pre" {
			text := nodeText(n)
			start := strings.Index(text, "First name:")
			if start >= 0 && strings.Contains(text[start:], "Surname:") {
				rows = append(rows, strings.TrimSpace(text[start:]))
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return rows
}

func newDVWAClient(baseURL string) (*http.Client, error) {
	origin, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: requestTimeout, Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
			return fmt.Errorf("redireccion fuera de DVWA o limite alcanzado")
		}
		return nil
	}}, nil
}

func dvwaPost(client *http.Client, targetURL string, values url.Values) (requestResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(values.Encode()))
	if err != nil {
		return requestResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "SQLi-Workshop-Scanner/2.0")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return requestResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil {
		return requestResult{}, err
	}
	if len(body) > responseLimit {
		return requestResult{}, fmt.Errorf("respuesta DVWA demasiado grande")
	}
	return requestResult{StatusCode: resp.StatusCode, Body: string(body), FinalURL: resp.Request.URL.String(), DurationMS: uint64(time.Since(start).Milliseconds())}, nil
}

type dvwaObserver func(models.LabActivityEvent)

func observeDVWA(observe dvwaObserver, event models.LabActivityEvent) {
	if observe != nil {
		observe(event)
	}
}

func dvwaRequest(client *http.Client, endpoint string, values url.Values, step models.LabActivityEvent, observe dvwaObserver) (requestResult, error) {
	step.Method, step.URL, step.State = http.MethodGet, endpoint, "running"
	if values != nil {
		step.Method = http.MethodPost
	}
	observeDVWA(observe, step)
	var result requestResult
	var err error
	if values == nil {
		result, err = performRequest(client, endpoint)
	} else {
		result, err = dvwaPost(client, endpoint, values)
	}
	if err != nil {
		step.State, step.Detail = "failed", err.Error()
		observeDVWA(observe, step)
		return result, err
	}
	step.State = "completed"
	step.StatusCode, step.DurationMS = &result.StatusCode, &result.DurationMS
	bytes := len(result.Body)
	step.ResponseBytes = &bytes
	if step.Stage == "probe" {
		rows := len(dvwaRows(result.Body))
		step.Records = &rows
		if signature := sqlErrorSignature(result.Body); signature != "" {
			step.Detail = "Firma SQL observada: " + signature
		}
	}
	if result.StatusCode >= 400 {
		step.State = "http_error"
	}
	observeDVWA(observe, step)
	return result, nil
}

func loginDVWA(client *http.Client, baseURL, username, password, level string, observe dvwaObserver) error {
	if level != "low" && level != "medium" {
		return fmt.Errorf("nivel DVWA no compatible")
	}
	step := func(id, summary string) models.LabActivityEvent {
		return models.LabActivityEvent{StepID: id, Stage: "session", Level: level, Summary: summary}
	}
	login, err := dvwaRequest(client, baseURL+"/login.php", nil, step("login-form", "Leer formulario de acceso y token CSRF"), observe)
	if err != nil {
		return err
	}
	if login.StatusCode != http.StatusOK {
		return fmt.Errorf("DVWA login HTTP %d", login.StatusCode)
	}
	token, err := csrfToken(login.Body)
	if err != nil {
		return err
	}
	result, err := dvwaRequest(client, baseURL+"/login.php", url.Values{"username": {username}, "password": {password}, "Login": {"Login"}, "user_token": {token}}, step("login-session", "Autenticar sesión de laboratorio"), observe)
	if err != nil {
		return err
	}
	if result.StatusCode != http.StatusOK || !strings.Contains(result.Body, "logout.php") || strings.Contains(result.FinalURL, "login.php") {
		return fmt.Errorf("no se pudo autenticar en DVWA; verifica sus credenciales e inicializacion")
	}
	security, err := dvwaRequest(client, baseURL+"/security.php", nil, step("security-form", "Leer configuración de seguridad"), observe)
	if err != nil {
		return err
	}
	token, err = csrfToken(security.Body)
	if err != nil {
		return err
	}
	result, err = dvwaRequest(client, baseURL+"/security.php", url.Values{"security": {level}, "seclev_submit": {"Submit"}, "user_token": {token}}, step("security-level", "Configurar nivel "+level), observe)
	if err != nil {
		return err
	}
	if result.StatusCode != http.StatusOK || !strings.Contains(result.Body, "<em>"+level+"</em>") {
		return fmt.Errorf("DVWA no confirmo el nivel %s", level)
	}
	return nil
}

func probeDVWA(client *http.Client, targetURL, level string, observe dvwaObserver) ([]models.PayloadExecutionEvent, error) {
	if level != "low" && level != "medium" {
		return nil, fmt.Errorf("nivel DVWA no compatible")
	}
	method := http.MethodGet
	if level == "medium" {
		method = http.MethodPost
	}
	probeTarget := func(value string) (string, url.Values, error) {
		if level == "medium" {
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
	requestNumber := 0
	request := func(value, summary string, allowSQLError bool) (requestResult, error) {
		probeURL, values, err := probeTarget(value)
		if err != nil {
			return requestResult{}, err
		}
		requestNumber++
		response, err := dvwaRequest(client, probeURL, values, models.LabActivityEvent{StepID: fmt.Sprintf("probe-%d", requestNumber), Stage: "probe", Level: level, Summary: summary, Payload: value, RequestNumber: requestNumber, RequestTotal: 6}, observe)
		if err != nil {
			return requestResult{}, err
		}
		if strings.Contains(response.FinalURL, "login.php") || strings.Contains(response.FinalURL, "setup.php") {
			return requestResult{}, fmt.Errorf("la sesion DVWA expiro o falta inicializar su base de datos")
		}
		if response.StatusCode != http.StatusOK && !(allowSQLError && response.StatusCode == 500 && sqlErrorSignature(response.Body) != "") {
			return requestResult{}, fmt.Errorf("DVWA respondio HTTP %d", response.StatusCode)
		}
		return response, nil
	}
	baseline, err := request("1", "Establecer línea base · id=1", false)
	if err != nil {
		return nil, err
	}
	baseRows := dvwaRows(baseline.Body)
	if len(baseRows) == 0 {
		return nil, fmt.Errorf("DVWA no devolvio registros base; verifica el modulo SQL Injection y nivel %s", level)
	}
	observeDVWA(observe, models.LabActivityEvent{StepID: "baseline-verified", Stage: "validation", State: "completed", Level: level, Summary: fmt.Sprintf("Línea base verificada · %d registro(s)", len(baseRows))})
	quote, err := request("1'", "Probar error SQL · comilla en id", true)
	if err != nil {
		return nil, err
	}
	quoteURL, quoteValues, _ := probeTarget("1'")
	errorEvent := models.PayloadExecutionEvent{Name: "DVWA · Error SQL", Parameter: "id", Payload: "1'", TestedURL: quoteURL, StatusCode: quote.StatusCode, BaselineSize: len(baseline.Body), ObservedSize: len(quote.Body), Result: "NOT_DETECTED", Risk: "LOW", ExecutionType: "REAL", Reason: "No se observo una firma nueva de error SQL.", Remediation: "Usar consultas preparadas y ocultar errores SQL en respuestas HTTP."}
	errorEvent.Method, errorEvent.DVWALevel = method, level
	errorEvent.BaselineDurationMS, errorEvent.ObservedDurationMS = &baseline.DurationMS, &quote.DurationMS
	if quoteValues != nil {
		errorEvent.RequestBody = quoteValues.Encode()
	}
	if signature := sqlErrorSignature(quote.Body); signature != "" && sqlErrorSignature(baseline.Body) == "" {
		errorEvent.Result, errorEvent.Risk, errorEvent.Reason = "DETECTED", "HIGH", "La entrada con comilla introdujo un error SQL: "+signature
	}
	trueValue, falseValue := "1' AND '1'='1", "1' AND '1'='2"
	if level == "medium" {
		trueValue, falseValue = "1 AND 1=1", "1 AND 1=2"
	}
	trueProbe, err := request(trueValue, "Condición verdadera · repetición 1/2", false)
	if err != nil {
		return []models.PayloadExecutionEvent{errorEvent}, err
	}
	falseProbe, err := request(falseValue, "Condición falsa · repetición 1/2", false)
	if err != nil {
		return []models.PayloadExecutionEvent{errorEvent}, err
	}
	trueRepeat, err := request(trueValue, "Condición verdadera · repetición 2/2", false)
	if err != nil {
		return []models.PayloadExecutionEvent{errorEvent}, err
	}
	falseRepeat, err := request(falseValue, "Condición falsa · repetición 2/2", false)
	if err != nil {
		return []models.PayloadExecutionEvent{errorEvent}, err
	}
	trueRows, falseRows := dvwaRows(trueProbe.Body), dvwaRows(falseProbe.Body)
	baseCount, trueCount, falseCount := len(baseRows), len(trueRows), len(falseRows)
	booleanURL, booleanValues, _ := probeTarget(falseValue)
	boolean := models.PayloadExecutionEvent{Name: "DVWA · Comparacion booleana", Parameter: "id", Payload: trueValue + " / " + falseValue, TestedURL: booleanURL, StatusCode: falseProbe.StatusCode, BaselineSize: len(baseline.Body), ObservedSize: len(falseProbe.Body), BaselineRecords: &baseCount, TrueRecords: &trueCount, ObservedRecords: &falseCount, Result: "NOT_DETECTED", Risk: "LOW", ExecutionType: "REAL", Reason: "Las condiciones no reprodujeron una diferencia booleana en los registros devueltos.", Remediation: "Separar id de la estructura SQL usando una consulta parametrizada."}
	boolean.Method, boolean.DVWALevel = method, level
	boolean.BaselineDurationMS, boolean.ObservedDurationMS = &baseline.DurationMS, &falseProbe.DurationMS
	if booleanValues != nil {
		boolean.RequestBody = booleanValues.Encode()
	}
	if strings.Join(trueRows, "\n") != strings.Join(dvwaRows(trueRepeat.Body), "\n") || strings.Join(falseRows, "\n") != strings.Join(dvwaRows(falseRepeat.Body), "\n") {
		boolean.Result, boolean.Reason = "INCONCLUSIVE", "Los registros variaron entre repeticiones; no hay evidencia booleana reproducible."
	} else if strings.Join(baseRows, "\n") == strings.Join(trueRows, "\n") && len(falseRows) == 0 {
		boolean.Result, boolean.Risk, boolean.Reason = "DETECTED", "HIGH", fmt.Sprintf("Dos repeticiones confirmaron %d registros con condicion verdadera y 0 con condicion falsa; evidencia HTTP de alteracion del filtro SQL.", len(trueRows))
	}
	return []models.PayloadExecutionEvent{errorEvent, boolean}, nil
}

func runDVWAScan(scanID, targetURL, level string, repo *database.Repository) error {
	origin, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	baseURL := origin.Scheme + "://" + origin.Host
	client, err := newDVWAClient(baseURL)
	if err != nil {
		return err
	}
	username, password := os.Getenv("DVWA_USERNAME"), os.Getenv("DVWA_PASSWORD")
	if username == "" || password == "" {
		return fmt.Errorf("configura DVWA_USERNAME y DVWA_PASSWORD en el backend")
	}
	observe := func(event models.LabActivityEvent) {
		message, err := json.Marshal(event)
		if err == nil {
			repo.CreateEventWithoutInterrupting(scanID, "LAB_ACTIVITY", string(message))
		}
	}
	if err := loginDVWA(client, baseURL, username, password, level, observe); err != nil {
		return err
	}
	repo.CreateEventWithoutInterrupting(scanID, "SESSION_AUTHENTICATED", fmt.Sprintf("Sesión DVWA autenticada; nivel %s confirmado.", level))
	events, probeErr := probeDVWA(client, targetURL, level, observe)
	if err := saveHTTPProbeEvents(scanID, events, repo); err != nil {
		return err
	}
	return probeErr
}
