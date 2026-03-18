package hunter

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

const hunterSearchURL = "https://hunter.qianxin.com/openApi/search"

type hunterResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int `json:"total"`
		Arr   []struct {
			URL      string      `json:"url"`
			IP       string      `json:"ip"`
			Port     json.Number `json:"port"`
			Protocol string      `json:"protocol"`
			WebTitle string      `json:"web_title"`
			Country  string      `json:"country"`
			Province string      `json:"province"`
			City     string      `json:"city"`
			Domain   string      `json:"domain"`
			ICP       string      `json:"icp"`
			ICPName   string      `json:"icp_name"`
			ICPCompany string     `json:"icp_company"`
			ICPUnit   string      `json:"icp_unit"`
			ICPSubject string     `json:"icp_subject"`
			ICPNumber string      `json:"icp_number"`
			ICPNo     string      `json:"number"`
		} `json:"arr"`
	} `json:"data"`
}

// Search performs a Hunter search and returns normalized results.
func Search(query string, size int, isWeb bool, apiKey string) ([]model.SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is empty")
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, errors.New("Hunter API key is not configured")
	}

	pageSize := normalizeSize(size)
	startTime := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	endTime := time.Now().Format("2006-01-02")

	params := url.Values{}
	params.Set("api-key", apiKey)
	params.Set("search", base64.RawURLEncoding.EncodeToString([]byte(query)))
	params.Set("page", "1")
	params.Set("page_size", strconv.Itoa(pageSize))
	if isWeb {
		params.Set("is_web", "1")
	} else {
		params.Set("is_web", "0")
	}
	params.Set("start_time", startTime)
	params.Set("end_time", endTime)

	req, err := http.NewRequest(http.MethodGet, hunterSearchURL+"?"+params.Encode(), nil)
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
		return nil, fmt.Errorf("Hunter request failed with status %s", resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	var result hunterResponse
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if result.Code != 200 {
		if result.Message != "" {
			return nil, errors.New(result.Message)
		}
		return nil, errors.New("Hunter API error")
	}

	items := make([]model.SearchResult, 0, len(result.Data.Arr))
	for _, item := range result.Data.Arr {
		port := parseNumber(item.Port)
		protocol := strings.TrimSpace(item.Protocol)
		urlValue := strings.TrimSpace(item.URL)
		if urlValue == "" {
			urlValue = buildURL(protocol, item.Domain, item.IP, port)
		}
		icp := firstNonEmpty(item.ICPName, item.ICPCompany, item.ICPUnit, item.ICPSubject, item.ICP)
		if icp == "" {
			icp = firstNonEmpty(item.ICPNumber, item.ICPNo)
		}

		items = append(items, model.SearchResult{
			URL:      urlValue,
			IP:       item.IP,
			Port:     port,
			Protocol: protocol,
			Location: joinLocation(item.Country, item.Province, item.City),
			Title:    item.WebTitle,
			ICP:      icp,
		})
	}

	return items, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
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

func parseNumber(num json.Number) int {
	if num == "" {
		return 0
	}
	value, err := num.Int64()
	if err != nil {
		return 0
	}
	return int(value)
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
