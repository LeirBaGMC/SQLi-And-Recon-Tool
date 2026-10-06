package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

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
		// Explicit feedback from our local corrected module; never infer rejection
		// from an empty response or a WAF/transport error.
		for _, validation := range []string{"accepted", "rejected", "error"} {
			if strings.Contains(result.Body, `data-workshop-validation="`+validation+`"`) {
				step.ValidationResult = validation
				break
			}
		}
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
	if level != "low" && level != "medium" && level != "high" {
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
