package fofa

import (
	"GoSecProbe/model"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const fofaSearchURL = "https://fofa.info/api/v1/search/all"

type fofaResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Results [][]any  `json:"results"`
	Size    int      `json:"size"`
	Page    int      `json:"page"`
	Query   string   `json:"query"`
	Mode    string   `json:"mode"`
	Link    string   `json:"link"`
	Message string   `json:"message"`
}

// Search performs a FOFA search and returns normalized results.
func Search(query string, size int, isWeb bool, apiKey string, apiEmail string) ([]model.SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is empty")
	}
	apiKey = strings.TrimSpace(apiKey)
	apiEmail = strings.TrimSpace(apiEmail)
	if apiKey == "" {
		return nil, errors.New("FOFA key is not configured")
	}

	pageSize := normalizeSize(size)
	if isWeb {
		query = addWebFilter(query)
	}

	fields := []string{"host", "ip", "port", "protocol", "country", "province", "city", "title", "icp_name", "icp"}
	params := url.Values{}
	params.Set("key", apiKey)
	if apiEmail != "" {
		params.Set("email", apiEmail)
	}
	params.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	params.Set("fields", strings.Join(fields, ","))
	params.Set("page", "1")
	params.Set("size", strconv.Itoa(pageSize))
	params.Set("full", "false")

	req, err := http.NewRequest(http.MethodGet, fofaSearchURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("FOFA request failed with status %s", resp.Status)
	}

	var result fofaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error {
		if result.ErrMsg != "" {
			return nil, errors.New(result.ErrMsg)
		}
		if result.Message != "" {
			return nil, errors.New(result.Message)
		}
		return nil, errors.New("FOFA API error")
	}

	items := make([]model.SearchResult, 0, len(result.Results))
	for _, row := range result.Results {
		if len(row) < len(fields) {
			continue
		}
		urlValue := toString(row[0])
		ip := toString(row[1])
		port := parseAnyInt(row[2])
		protocol := toString(row[3])
		location := joinLocation(toString(row[4]), toString(row[5]), toString(row[6]))
		title := toString(row[7])
		icpName := toString(row[8])
		icpNumber := toString(row[9])
		icp := strings.TrimSpace(icpName)
		if icp == "" {
			icp = strings.TrimSpace(icpNumber)
		}

		if urlValue == "" {
			urlValue = buildURL(protocol, "", ip, port)
		}

		items = append(items, model.SearchResult{
			URL:      urlValue,
			IP:       ip,
			Port:     port,
			Protocol: protocol,
			Location: location,
			Title:    title,
			ICP:      icp,
		})
	}

	return items, nil
}

func normalizeSize(size int) int {
	if size <= 0 {
		return 10
	}
	if size > 1000 {
		return 1000
	}
	return size
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(value)
	}
}

func parseAnyInt(value any) int {
	switch v := value.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return 0
}

func addWebFilter(query string) string {
	if strings.Contains(query, "protocol=\"http\"") || strings.Contains(query, "protocol=\"https\"") {
		return query
	}
	return fmt.Sprintf("(%s) && (protocol=\"http\" || protocol=\"https\")", query)
}

func joinLocation(parts ...string) string {
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "0" {
			continue
		}
		segments = append(segments, part)
	}
	return strings.Join(segments, " ")
}

func buildURL(protocol, domain, ip string, port int) string {
	host := strings.TrimSpace(domain)
	if host == "" {
		host = strings.TrimSpace(ip)
	}
	if host == "" {
		return ""
	}
	if protocol == "" {
		if port == 443 {
			protocol = "https"
		} else if port == 80 {
			protocol = "http"
		}
	}
	if protocol != "" && !strings.HasPrefix(host, protocol+"://") {
		host = protocol + "://" + host
	}
	return appendPort(host, port)
}

func appendPort(host string, port int) string {
	if port <= 0 {
		return host
	}
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err == nil && parsed.Host != "" {
			if strings.Contains(parsed.Host, ":") {
				return host
			}
			parsed.Host = parsed.Host + ":" + strconv.Itoa(port)
			return parsed.String()
		}
	}
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":" + strconv.Itoa(port)
}
