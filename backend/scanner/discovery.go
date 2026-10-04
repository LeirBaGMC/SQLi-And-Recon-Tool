package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	discoveryPageLimit    = 20
	discoveryDepthLimit   = 2
	discoveryBodyLimit    = 1048576
	discoveryRequestLimit = 8 * time.Second
)

type DiscoveryCandidate struct {
	URL           string
	ParameterName string
	OriginalValue string
	SourceURL     string
}

type DiscoverySummary struct {
	StartURL             string
	PagesVisited         int
	LinksDiscovered      int
	CandidatesDiscovered int
}

type discoveryQueueItem struct {
	URL   string
	Depth int
}

func DiscoverCandidates(
	startURL string,
) ([]DiscoveryCandidate, DiscoverySummary, error) {
	summary := DiscoverySummary{
		StartURL: startURL,
	}

	parsedStartURL, err := url.Parse(startURL)
	if err != nil {
		return nil, summary, fmt.Errorf(
			"no se pudo interpretar la URL inicial: %w",
			err,
		)
	}

	if parsedStartURL.Scheme != "http" &&
		parsedStartURL.Scheme != "https" {
		return nil, summary, fmt.Errorf(
			"el descubrimiento solo admite HTTP o HTTPS",
		)
	}

	startHostname := strings.ToLower(
		parsedStartURL.Hostname(),
	)

	if startHostname == "" {
		return nil, summary, fmt.Errorf(
			"la URL inicial no contiene un dominio valido",
		)
	}

	client := http.Client{
		Timeout: discoveryRequestLimit,
		CheckRedirect: func(
			request *http.Request,
			previousRequests []*http.Request,
		) error {
			redirectHostname := strings.ToLower(
				request.URL.Hostname(),
			)

			if redirectHostname != startHostname {
				return fmt.Errorf(
					"la redireccion apunta a otro dominio",
				)
			}

			if len(previousRequests) >= 5 {
				return fmt.Errorf(
					"se alcanzo el limite de redirecciones",
				)
			}

			return nil
		},
	}

	initialURL := normalizeDiscoveredURL(
		parsedStartURL,
	)

	queue := []discoveryQueueItem{
		{
			URL:   initialURL,
			Depth: 0,
		},
	}

	visitedPages := make(map[string]bool)
	queuedPages := map[string]bool{
		initialURL: true,
	}

	candidateKeys := make(map[string]bool)
	candidates := make([]DiscoveryCandidate, 0)

	for len(queue) > 0 &&
		summary.PagesVisited < discoveryPageLimit {
		currentItem := queue[0]
		queue = queue[1:]

		if visitedPages[currentItem.URL] {
			continue
		}

		visitedPages[currentItem.URL] = true

		pageResult, err := fetchDiscoveryPage(
			client,
			currentItem.URL,
			startHostname,
		)
		if err != nil {
			continue
		}

		summary.PagesVisited++

		pageCandidates := extractCandidates(
			pageResult.FinalURL,
			pageResult.FinalURL,
		)

		appendUniqueCandidates(
			&candidates,
			candidateKeys,
			pageCandidates,
		)

		if currentItem.Depth >= discoveryDepthLimit {
			continue
		}

		links := extractPageLinks(
			pageResult.Body,
			pageResult.FinalURL,
			startHostname,
		)

		summary.LinksDiscovered += len(links)

		for _, discoveredURL := range links {
			discoveredCandidates := extractCandidates(
				discoveredURL,
				pageResult.FinalURL,
			)

			appendUniqueCandidates(
				&candidates,
				candidateKeys,
				discoveredCandidates,
			)

			pageURL := removeQueryValues(
				discoveredURL,
			)

			if pageURL == "" {
				continue
			}

			if visitedPages[pageURL] ||
				queuedPages[pageURL] {
				continue
			}

			if len(queuedPages) >= discoveryPageLimit {
				continue
			}

			queuedPages[pageURL] = true

			queue = append(
				queue,
				discoveryQueueItem{
					URL: pageURL,
					Depth: currentItem.Depth +
						1,
				},
			)
		}
	}

	sort.Slice(
		candidates,
		func(firstIndex int, secondIndex int) bool {
			if candidates[firstIndex].URL !=
				candidates[secondIndex].URL {
				return candidates[firstIndex].URL <
					candidates[secondIndex].URL
			}

			return candidates[firstIndex].ParameterName <
				candidates[secondIndex].ParameterName
		},
	)

	summary.CandidatesDiscovered = len(candidates)

	return candidates, summary, nil
}

type discoveryPageResult struct {
	FinalURL string
	Body     string
}

func fetchDiscoveryPage(
	client http.Client,
	targetURL string,
	allowedHostname string,
) (discoveryPageResult, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		discoveryRequestLimit,
	)
	defer cancel()

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		targetURL,
		nil,
	)
	if err != nil {
		return discoveryPageResult{}, err
	}

	request.Header.Set(
		"User-Agent",
		"SQLi-Workshop-Discovery",
	)

	request.Header.Set(
		"Accept",
		"text/html,application/xhtml+xml",
	)

	response, err := client.Do(request)
	if err != nil {
		return discoveryPageResult{}, err
	}
	defer response.Body.Close()

	finalHostname := strings.ToLower(
		response.Request.URL.Hostname(),
	)

	if finalHostname != allowedHostname {
		return discoveryPageResult{}, fmt.Errorf(
			"la respuesta final pertenece a otro dominio",
		)
	}

	contentType := strings.ToLower(
		response.Header.Get("Content-Type"),
	)

	if !strings.Contains(contentType, "text/html") &&
		!strings.Contains(
			contentType,
			"application/xhtml+xml",
		) {
		return discoveryPageResult{}, fmt.Errorf(
			"la respuesta no contiene una pagina HTML",
		)
	}

	bodyBytes, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			discoveryBodyLimit,
		),
	)
	if err != nil {
		return discoveryPageResult{}, err
	}

	return discoveryPageResult{
		FinalURL: response.Request.URL.String(),
		Body:     string(bodyBytes),
	}, nil
}

func extractPageLinks(
	body string,
	baseURL string,
	allowedHostname string,
) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return []string{}
	}

	tokenizer := html.NewTokenizer(
		strings.NewReader(body),
	)

	discoveredLinks := make(map[string]bool)

	for {
		tokenType := tokenizer.Next()

		if tokenType == html.ErrorToken {
			break
		}

		if tokenType != html.StartTagToken &&
			tokenType != html.SelfClosingTagToken {
			continue
		}

		token := tokenizer.Token()

		if token.Data != "a" {
			continue
		}

		reference := ""

		for _, attribute := range token.Attr {
			if strings.EqualFold(
				attribute.Key,
				"href",
			) {
				reference = strings.TrimSpace(
					attribute.Val,
				)

				break
			}
		}

		if reference == "" {
			continue
		}

		resolvedURL, allowed := resolveDiscoveredLink(
			base,
			reference,
			allowedHostname,
		)
		if !allowed {
			continue
		}

		discoveredLinks[resolvedURL] = true
	}

	result := make(
		[]string,
		0,
		len(discoveredLinks),
	)

	for discoveredURL := range discoveredLinks {
		result = append(
			result,
			discoveredURL,
		)
	}

	sort.Strings(result)

	return result
}

func resolveDiscoveredLink(
	baseURL *url.URL,
	reference string,
	allowedHostname string,
) (string, bool) {
	lowerReference := strings.ToLower(
		reference,
	)

	if strings.HasPrefix(
		lowerReference,
		"javascript:",
	) {
		return "", false
	}

	if strings.HasPrefix(
		lowerReference,
		"mailto:",
	) {
		return "", false
	}

	if strings.HasPrefix(
		lowerReference,
		"tel:",
	) {
		return "", false
	}

	if strings.HasPrefix(
		lowerReference,
		"data:",
	) {
		return "", false
	}

	referenceURL, err := url.Parse(reference)
	if err != nil {
		return "", false
	}

	resolvedURL := baseURL.ResolveReference(
		referenceURL,
	)

	if resolvedURL.Scheme != "http" &&
		resolvedURL.Scheme != "https" {
		return "", false
	}

	if !strings.EqualFold(
		resolvedURL.Hostname(),
		allowedHostname,
	) {
		return "", false
	}

	resolvedURL.Fragment = ""

	if shouldIgnorePath(resolvedURL.Path) {
		return "", false
	}

	return normalizeDiscoveredURL(
		resolvedURL,
	), true
}

func extractCandidates(
	rawURL string,
	sourceURL string,
) []DiscoveryCandidate {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return []DiscoveryCandidate{}
	}

	queryValues := parsedURL.Query()

	if len(queryValues) == 0 {
		return []DiscoveryCandidate{}
	}

	parameterNames := make(
		[]string,
		0,
		len(queryValues),
	)

	for parameterName := range queryValues {
		parameterNames = append(
			parameterNames,
			parameterName,
		)
	}

	sort.Strings(parameterNames)

	candidates := make(
		[]DiscoveryCandidate,
		0,
		len(parameterNames),
	)

	for _, parameterName := range parameterNames {
		normalizedName := strings.TrimSpace(
			parameterName,
		)

		if normalizedName == "" ||
			len(normalizedName) > 100 {
			continue
		}

		values := queryValues[parameterName]

		if len(values) == 0 {
			continue
		}

		originalValue := strings.TrimSpace(
			values[0],
		)

		if originalValue == "" ||
			len(originalValue) > 500 {
			continue
		}

		candidates = append(
			candidates,
			DiscoveryCandidate{
				URL: normalizeDiscoveredURL(
					parsedURL,
				),
				ParameterName: normalizedName,
				OriginalValue: originalValue,
				SourceURL:     sourceURL,
			},
		)
	}

	return candidates
}

func appendUniqueCandidates(
	destination *[]DiscoveryCandidate,
	candidateKeys map[string]bool,
	newCandidates []DiscoveryCandidate,
) {
	for _, candidate := range newCandidates {
		candidateKey := strings.Join(
			[]string{
				candidate.URL,
				candidate.ParameterName,
			},
			"|",
		)

		if candidateKeys[candidateKey] {
			continue
		}

		candidateKeys[candidateKey] = true

		*destination = append(
			*destination,
			candidate,
		)
	}
}

func normalizeDiscoveredURL(
	parsedURL *url.URL,
) string {
	normalizedURL := *parsedURL

	normalizedURL.Fragment = ""

	if normalizedURL.Path == "" {
		normalizedURL.Path = "/"
	}

	normalizedURL.Host = strings.ToLower(
		normalizedURL.Host,
	)

	return normalizedURL.String()
}

func removeQueryValues(
	rawURL string,
) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return normalizeDiscoveredURL(
		parsedURL,
	)
}

func shouldIgnorePath(
	targetPath string,
) bool {
	extension := strings.ToLower(
		path.Ext(targetPath),
	)

	ignoredExtensions := map[string]bool{
		".css":   true,
		".js":    true,
		".json":  true,
		".xml":   true,
		".jpg":   true,
		".jpeg":  true,
		".png":   true,
		".gif":   true,
		".svg":   true,
		".webp":  true,
		".ico":   true,
		".woff":  true,
		".woff2": true,
		".ttf":   true,
		".eot":   true,
		".pdf":   true,
		".zip":   true,
		".rar":   true,
		".7z":    true,
		".gz":    true,
		".mp3":   true,
		".mp4":   true,
		".avi":   true,
		".mov":   true,
	}

	if ignoredExtensions[extension] {
		return true
	}

	lowerPath := strings.ToLower(
		targetPath,
	)

	ignoredFragments := []string{
		"/logout",
		"/logoff",
		"/signout",
		"/delete",
		"/remove",
		"/destroy",
	}

	for _, ignoredFragment := range ignoredFragments {
		if strings.Contains(
			lowerPath,
			ignoredFragment,
		) {
			return true
		}
	}

	return false
}
