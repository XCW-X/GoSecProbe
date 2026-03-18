package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ConvertHTTPToYamlRequest HTTP请求包转YAML的请求体
type ConvertHTTPToYamlRequest struct {
	RawHTTP     string `json:"raw_http" binding:"required"` // 原始HTTP请求包
	PocName     string `json:"poc_name"`                    // POC名称（可选）
	Severity    string `json:"severity"`                    // 危害等级（可选，默认medium）
	Description string `json:"description"`                 // 描述（可选）
	Author      string `json:"author"`                      // 作者（可选）
	MatchType   string `json:"match_type"`                  // 匹配类型：status/word/regex（可选，默认status）
	MatchValue  string `json:"match_value"`                 // 匹配值（可选）
}

// ConvertHTTPToYaml 将HTTP请求包转换为Nuclei YAML模板
func ConvertHTTPToYaml(c *gin.Context) {
	var req ConvertHTTPToYamlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 解析HTTP请求包
	parsed, err := parseRawHTTP(req.RawHTTP)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 40000,
			"msg":  "HTTP请求包解析失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 生成YAML模板
	yaml := generateNucleiYaml(parsed, &req)

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "转换成功",
		"data": gin.H{
			"yaml_content": yaml,
			"parsed_info": gin.H{
				"method":        parsed.Method,
				"path":          parsed.Path,
				"host":          parsed.Host,
				"headers_count": len(parsed.Headers),
				"has_body":      parsed.Body != "",
			},
		},
	})
}

// parsedHTTPRequest 解析后的HTTP请求结构
type parsedHTTPRequest struct {
	Method  string
	Path    string
	Host    string
	Headers []headerPair
	Body    string
	Scheme  string
}

type headerPair struct {
	Key   string
	Value string
}

// parseRawHTTP 解析原始HTTP请求文本
func parseRawHTTP(raw string) (*parsedHTTPRequest, error) {
	// 统一换行符
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.TrimSpace(raw)

	if raw == "" {
		return nil, fmt.Errorf("HTTP请求包内容为空")
	}

	// 分离请求头和请求体
	headerBody := strings.SplitN(raw, "\n\n", 2)
	headerSection := headerBody[0]
	body := ""
	if len(headerBody) > 1 {
		body = strings.TrimSpace(headerBody[1])
	}

	lines := strings.Split(headerSection, "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("无法解析请求行")
	}

	// 解析请求行: GET /path HTTP/1.1
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("请求行格式错误: %s", requestLine)
	}

	method := strings.ToUpper(parts[0])
	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true,
	}
	if !validMethods[method] {
		return nil, fmt.Errorf("不支持的HTTP方法: %s", method)
	}

	path := parts[1]

	// 解析请求头
	var headers []headerPair
	host := ""
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])
		if strings.EqualFold(key, "Host") {
			host = value
		}
		headers = append(headers, headerPair{Key: key, Value: value})
	}

	if host == "" {
		// 尝试从路径中解析host
		if strings.HasPrefix(path, "http") {
			u, err := url.Parse(path)
			if err == nil {
				host = u.Host
				path = u.RequestURI()
			}
		}
		if host == "" {
			host = "{{Hostname}}"
		}
	}

	// 检测scheme
	scheme := "http"
	for _, h := range headers {
		// 如果有Referer/Origin是https，推断scheme
		if strings.EqualFold(h.Key, "Referer") || strings.EqualFold(h.Key, "Origin") {
			if strings.HasPrefix(h.Value, "https") {
				scheme = "https"
			}
		}
	}

	return &parsedHTTPRequest{
		Method:  method,
		Path:    path,
		Host:    host,
		Headers: headers,
		Body:    body,
		Scheme:  scheme,
	}, nil
}

// generateNucleiYaml 基于解析后的HTTP请求生成Nuclei YAML模板
func generateNucleiYaml(parsed *parsedHTTPRequest, req *ConvertHTTPToYamlRequest) string {
	var sb strings.Builder

	// 生成template ID
	templateID := generateTemplateID(req.PocName)
	pocName := req.PocName
	if pocName == "" {
		pocName = fmt.Sprintf("Custom POC - %s %s", parsed.Method, parsed.Path)
	}
	author := req.Author
	if author == "" {
		author = "GoSecProbe"
	}
	severity := req.Severity
	if severity == "" {
		severity = "medium"
	}
	description := req.Description
	if description == "" {
		description = fmt.Sprintf("Auto-generated from HTTP request: %s %s", parsed.Method, parsed.Path)
	}

	// info 部分
	sb.WriteString(fmt.Sprintf("id: %s\n\n", templateID))
	sb.WriteString("info:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", pocName))
	sb.WriteString(fmt.Sprintf("  author: %s\n", author))
	sb.WriteString(fmt.Sprintf("  severity: %s\n", severity))
	sb.WriteString(fmt.Sprintf("  description: %s\n", description))
	sb.WriteString("  tags: custom,http\n")
	sb.WriteString("  metadata:\n")
	sb.WriteString(fmt.Sprintf("    max-request: 1\n"))

	// http 部分
	sb.WriteString("\nhttp:\n")
	sb.WriteString("  - raw:\n")
	sb.WriteString("      - |\n")

	// 构建请求行 - 使用 raw request 格式
	sb.WriteString(fmt.Sprintf("        %s %s HTTP/1.1\n", parsed.Method, parsed.Path))
	sb.WriteString(fmt.Sprintf("        Host: {{Hostname}}\n"))

	// 添加请求头（过滤掉Host、Content-Length等nuclei自动处理的头）
	skipHeaders := map[string]bool{
		"host":            true,
		"content-length":  true,
		"connection":      true,
		"accept-encoding": true,
	}
	for _, h := range parsed.Headers {
		if skipHeaders[strings.ToLower(h.Key)] {
			continue
		}
		sb.WriteString(fmt.Sprintf("        %s: %s\n", h.Key, h.Value))
	}

	// 添加请求体
	if parsed.Body != "" {
		sb.WriteString("\n")
		// 请求体需要每行缩进
		bodyLines := strings.Split(parsed.Body, "\n")
		for _, line := range bodyLines {
			sb.WriteString(fmt.Sprintf("        %s\n", line))
		}
	}

	// 匹配器
	sb.WriteString("\n    matchers-condition: and\n")
	sb.WriteString("    matchers:\n")

	matchType := req.MatchType
	matchValue := req.MatchValue

	if matchType == "" || matchType == "status" {
		// 默认匹配状态码200
		statusCode := "200"
		if matchValue != "" {
			statusCode = matchValue
		}
		sb.WriteString("      - type: status\n")
		sb.WriteString(fmt.Sprintf("        status:\n"))
		sb.WriteString(fmt.Sprintf("          - %s\n", statusCode))
	} else if matchType == "word" {
		if matchValue != "" {
			sb.WriteString("      - type: word\n")
			sb.WriteString("        words:\n")
			// 支持多个匹配词，用逗号分隔
			words := strings.Split(matchValue, ",")
			for _, w := range words {
				w = strings.TrimSpace(w)
				if w != "" {
					sb.WriteString(fmt.Sprintf("          - \"%s\"\n", w))
				}
			}
		} else {
			// 没有指定匹配值，使用默认状态码匹配
			sb.WriteString("      - type: status\n")
			sb.WriteString("        status:\n")
			sb.WriteString("          - 200\n")
		}
	} else if matchType == "regex" {
		if matchValue != "" {
			sb.WriteString("      - type: regex\n")
			sb.WriteString("        regex:\n")
			sb.WriteString(fmt.Sprintf("          - \"%s\"\n", matchValue))
		} else {
			sb.WriteString("      - type: status\n")
			sb.WriteString("        status:\n")
			sb.WriteString("          - 200\n")
		}
	}

	return sb.String()
}

// generateTemplateID 根据POC名称生成模板ID
func generateTemplateID(name string) string {
	if name == "" {
		return fmt.Sprintf("custom-poc-%s", time.Now().Format("20060102-150405"))
	}

	// 移除特殊字符，转为小写，空格替换为横杠
	id := strings.ToLower(name)
	reg := regexp.MustCompile(`[^a-z0-9\-\s]`)
	id = reg.ReplaceAllString(id, "")
	id = strings.ReplaceAll(id, " ", "-")

	// 去掉连续横杠
	for strings.Contains(id, "--") {
		id = strings.ReplaceAll(id, "--", "-")
	}
	id = strings.Trim(id, "-")

	if id == "" {
		id = fmt.Sprintf("custom-poc-%s", time.Now().Format("20060102-150405"))
	}

	return id
}
