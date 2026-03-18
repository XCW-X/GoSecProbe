package quake

import (
	"GoSecProbe/model"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const quakeSearchURL = "https://quake.360.net/api/v3/search/quake_service"

type quakeSearchRequest struct {
	Query string `json:"query"`
	Start int    `json:"start"`
	Size  int    `json:"size"`
}

type quakeSearchResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			Http struct {
				Host  string `json:"host"`
				Title string `json:"title"`
			} `json:"http"`
		} `json:"service"`
		Port     int      `json:"port"`
		IP       string   `json:"ip"`
		Domain   []string `json:"domain"`
		Hostname []string `json:"hostname"`
		ICP      struct {
			Name   string `json:"name"`
			Number string `json:"number"`
		} `json:"icp"`
		ICPName string `json:"icp_name"`
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Search performs a Quake search and returns normalized results.
func Search(query string, size int, isWeb bool, apiKey string) ([]model.SearchResult, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, errors.New("query is empty")
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, errors.New("Quake key is not configured")
	}

	pageSize := normalizeSize(size)
	reqBody := quakeSearchRequest{
		Query: query,
		Start: 0,
		Size:  pageSize,
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, quakeSearchURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-QuakeToken", apiKey)

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Quake request failed with status %s", resp.Status)
	}

	var result quakeSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Code != 0 && result.Code != 200 {
		if result.Message != "" {
			return nil, errors.New(result.Message)
		}
		return nil, errors.New("Quake API error")
	}

	items := make([]model.SearchResult, 0, len(result.Data))
	for _, item := range result.Data {
		urlValue := strings.TrimSpace(item.Service.Http.Host)
		if urlValue == "" && len(item.Domain) > 0 {
			urlValue = item.Domain[0]
		}
		if urlValue == "" && len(item.Hostname) > 0 {
			urlValue = item.Hostname[0]
		}

		protocol := ""
		if item.Port == 443 {
			protocol = "https"
		} else if item.Port == 80 {
			protocol = "http"
		}
		if urlValue == "" {
			urlValue = buildURL(protocol, "", item.IP, item.Port)
		}

		if isWeb && item.Service.Http.Title == "" && !strings.Contains(urlValue, "http") {
			continue
		}

		icp := strings.TrimSpace(item.ICPName)
		if icp == "" {
			icp = strings.TrimSpace(item.ICP.Name)
		}
		if icp == "" {
			icp = strings.TrimSpace(item.ICP.Number)
		}

		items = append(items, model.SearchResult{
			URL:      urlValue,
			IP:       item.IP,
			Port:     item.Port,
			Protocol: protocol,
			Location: "",
			Title:    item.Service.Http.Title,
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
