package scanweb

import (
	"GoSecProbe/common/log"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// WebFingerprint 表示一个Web指纹识别结果
type WebFingerprint struct {
	URL           string            `json:"url"`            // 目标URL
	IP            string            `json:"ip"`             // IP地址
	Port          int               `json:"port"`           // 端口
	Title         string            `json:"title"`          // 网页标题
	StatusCode    int               `json:"status_code"`    // HTTP状态码
	Server        string            `json:"server"`         // Server头信息
	Technologies  []string          `json:"technologies"`   // 识别到的技术栈 (Wappalyzer)
	Frameworks    []string          `json:"frameworks"`     // 识别到的应用框架 (GoSecProbe)
	MatchedRules  []string          `json:"matched_rules"`  // 匹配到的具体规则详情
	FaviconHash   string            `json:"favicon_hash"`   // Favicon哈希
	Headers       map[string]string `json:"headers"`        // HTTP响应头
	ContentType   string            `json:"content_type"`   // Content-Type
	ContentLength int64             `json:"content_length"` // Content-Length
	ResponseTime  int64             `json:"response_time"`  // 响应时间(ms)
}

// WebScanner Web指纹扫描器
type WebScanner struct {
	Timeout         time.Duration
	MaxBodySize     int64
	wappalyzer      *wappalyzer.Wappalyze
	GoSecProbeMatcher *GoSecProbeMatcher // GoSecProbe指纹匹配器
	client          *http.Client
}

// NewWebScanner 创建Web扫描器实例
func NewWebScanner(timeout time.Duration) (*WebScanner, error) {
	// 初始化wappalyzer
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		return nil, fmt.Errorf("初始化wappalyzer失败: %v", err)
	}

	// 初始化GoSecProbe匹配器
	GoSecProbeMatcher, err := NewGoSecProbeMatcher()
	if err != nil {
		// GoSecProbe匹配器初始化失败不影响主流程，只记录错误
		log.Info("[Web扫描] 警告: 初始化GoSecProbe匹配器失败: %v", err)
		GoSecProbeMatcher = nil
	} else {
		log.Info("[Web扫描] 成功加载 %d 条 GoSecProbe 指纹规则", GoSecProbeMatcher.GetMatchedCount())
	}

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 忽略证书验证
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 最多允许3次重定向
			if len(via) >= 3 {
				return fmt.Errorf("停止重定向")
			}
			return nil
		},
	}

	return &WebScanner{
		Timeout:         timeout,
		MaxBodySize:     10 * 1024 * 1024, // 最大10MB
		wappalyzer:      wappalyzerClient,
		GoSecProbeMatcher: GoSecProbeMatcher,
		client:          client,
	}, nil
}

// ScanURL 扫描单个URL并识别Web指纹
func (s *WebScanner) ScanURL(ctx context.Context, targetURL string) (*WebFingerprint, error) {
	startTime := time.Now()

	// 解析URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("无效的URL: %v", err)
	}

	// 确保URL包含scheme
	if parsedURL.Scheme == "" {
		// 尝试HTTPS
		targetURL = "https://" + targetURL
		parsedURL, _ = url.Parse(targetURL)
	}

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置常见的User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	// 发送HTTP请求
	resp, err := s.client.Do(req)
	if err != nil {
		// 如果HTTPS失败，尝试HTTP
		if parsedURL.Scheme == "https" {
			httpURL := strings.Replace(targetURL, "https://", "http://", 1)
			req, _ = http.NewRequestWithContext(ctx, "GET", httpURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			resp, err = s.client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("HTTP请求失败: %v", err)
			}
			targetURL = httpURL
			parsedURL, _ = url.Parse(httpURL)
		} else {
			return nil, fmt.Errorf("HTTP请求失败: %v", err)
		}
	}
	defer resp.Body.Close()

	// 计算响应时间
	responseTime := time.Since(startTime).Milliseconds()

	// 读取响应体（限制大小）
	limitedReader := io.LimitReader(resp.Body, s.MaxBodySize)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	// 提取响应头信息
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// 提取网页标题
	title := extractTitle(string(bodyBytes))

	// 获取favicon哈希
	faviconHash := ""
	if s.GoSecProbeMatcher != nil {
		favHash, _ := DownloadFavicon(fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host), s.client)
		faviconHash = favHash
	}

	// 使用wappalyzer识别技术栈
	fingerprintMap := s.wappalyzer.Fingerprint(resp.Header, bodyBytes)
	technologies := make([]string, 0, len(fingerprintMap))
	for tech := range fingerprintMap {
		technologies = append(technologies, tech)
	}

	// 使用GoSecProbe匹配器识别
	frameworks := make([]string, 0)
	var matchedRules []string
	if s.GoSecProbeMatcher != nil {
		frameworks, matchedRules = s.GoSecProbeMatcher.MatchResponse(resp, string(bodyBytes), title, faviconHash)
	}

	// 结果去重 (Technologies)
	uniqueTechs := make([]string, 0)
	techMap := make(map[string]bool)
	for _, tech := range technologies {
		if !techMap[tech] && tech != "" {
			techMap[tech] = true
			uniqueTechs = append(uniqueTechs, tech)
		}
	}
	technologies = uniqueTechs

	// 结果去重 (Frameworks)
	uniqueFrameworks := make([]string, 0)
	frameworkMap := make(map[string]bool)
	for _, fw := range frameworks {
		if !frameworkMap[fw] && fw != "" {
			frameworkMap[fw] = true
			uniqueFrameworks = append(uniqueFrameworks, fw)
		}
	}
	frameworks = uniqueFrameworks

	// 获取端口
	port := 80
	if parsedURL.Scheme == "https" {
		port = 443
	}
	if parsedURL.Port() != "" {
		fmt.Sscanf(parsedURL.Port(), "%d", &port)
	}

	// 构建指纹结果
	fingerprint := &WebFingerprint{
		URL:           targetURL,
		IP:            parsedURL.Hostname(),
		Port:          port,
		Title:         title,
		StatusCode:    resp.StatusCode,
		Server:        headers["Server"],
		Technologies:  technologies,
		Frameworks:    frameworks,
		MatchedRules:  matchedRules,
		FaviconHash:   faviconHash,
		Headers:       headers,
		ContentType:   headers["Content-Type"],
		ContentLength: resp.ContentLength,
		ResponseTime:  responseTime,
	}

	return fingerprint, nil
}

// extractTitle 从HTML中提取title标签内容
func extractTitle(html string) string {
	// 简单的title提取，寻找<title>标签
	start := strings.Index(strings.ToLower(html), "<title>")
	if start == -1 {
		return ""
	}
	start += 7 // len("<title>")

	end := strings.Index(strings.ToLower(html[start:]), "</title>")
	if end == -1 {
		return ""
	}

	title := html[start : start+end]
	title = strings.TrimSpace(title)

	// 限制标题长度
	if len(title) > 200 {
		title = title[:200] + "..."
	}

	return title
}

// ScanURLs 批量扫描多个URL
func (s *WebScanner) ScanURLs(ctx context.Context, urls []string, onResult func(*WebFingerprint)) error {
	for _, targetURL := range urls {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fingerprint, err := s.ScanURL(ctx, targetURL)
			if err != nil {
				// 继续处理下一个URL
				continue
			}
			if onResult != nil {
				onResult(fingerprint)
			}
		}
	}
	return nil
}
