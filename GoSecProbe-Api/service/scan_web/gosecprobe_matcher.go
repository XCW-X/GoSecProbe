package scanweb

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// GoSecProbeFingerprint GoSecProbe指纹定义
type GoSecProbeFingerprint struct {
	ID      string `json:"id"`
	Product struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
		Vendor    string `json:"vendor"`
		Metadata  struct {
			FofaQuery   []string `json:"fofa_query"`
			GoogleQuery []string `json:"google_query"`
			ShodanQuery []string `json:"shodan_query"`
			Source      string   `json:"_source"`
		} `json:"metadata"`
	} `json:"product"`
	Fingerprint struct {
		Rules []FingerprintRule `json:"rules"`
	} `json:"fingerprint"`
}

// FingerprintRule 指纹规则
type FingerprintRule struct {
	RuleID    string `json:"rule_id"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Location  string `json:"location"`
	MatchType string `json:"match_type"`
	Pattern   string `json:"pattern"`
}

// GoSecProbeMatcher GoSecProbe规则匹配器
type GoSecProbeMatcher struct {
	fingerprints []GoSecProbeFingerprint
	mu           sync.RWMutex
}

// NewGoSecProbeMatcher 创建GoSecProbe匹配器
func NewGoSecProbeMatcher() (*GoSecProbeMatcher, error) {
	matcher := &GoSecProbeMatcher{
		fingerprints: make([]GoSecProbeFingerprint, 0),
	}

	// 加载指纹库
	if err := matcher.LoadFingerprints(); err != nil {
		return nil, fmt.Errorf("加载GoSecProbe指纹库失败: %v", err)
	}

	return matcher, nil
}

// LoadFingerprints 加载GoSecProbe指纹库
func (m *GoSecProbeMatcher) LoadFingerprints() error {
	// 获取当前程序路径
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %v", err)
	}
	baseDir := filepath.Dir(execPath)

	// 尝试多个可能的路径
	possiblePaths := []string{
		filepath.Join(baseDir, "service", "lib", "GoSecProbe.json"),
		filepath.Join(baseDir, "lib", "GoSecProbe.json"),
		"service/lib/GoSecProbe.json",
		"lib/GoSecProbe.json",
		"../lib/GoSecProbe.json",
		"../../lib/GoSecProbe.json",
	}

	var fingerprintPath string
	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			fingerprintPath = p
			break
		}
	}

	if fingerprintPath == "" {
		return fmt.Errorf("找不到 GoSecProbe.json 指纹文件")
	}

	// 读取指纹文件
	data, err := os.ReadFile(fingerprintPath)
	if err != nil {
		return fmt.Errorf("读取指纹文件 (%s) 失败: %v", fingerprintPath, err)
	}

	// 解析JSON
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := json.Unmarshal(data, &m.fingerprints); err != nil {
		return fmt.Errorf("解析指纹JSON失败: %v", err)
	}

	return nil
}

// MatchResponse 匹配HTTP响应
func (m *GoSecProbeMatcher) MatchResponse(resp *http.Response, body string, title string, faviconHash string) ([]string, []string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	matchedProducts := make(map[string]bool)
	names := make([]string, 0)
	reasons := make([]string, 0)

	// 提取headers到map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[strings.ToLower(key)] = strings.ToLower(values[0])
		}
	}

	bodyLower := strings.ToLower(body)
	titleLower := strings.ToLower(title)

	// 遍历所有指纹
	for _, fp := range m.fingerprints {
		// 如果已经匹配过该产品，跳过
		if matchedProducts[fp.Product.Name] {
			continue
		}

		// 检查所有规则并记录匹配到的具体规则
		for _, rule := range fp.Fingerprint.Rules {
			if m.matchRule(rule, headers, body, bodyLower, title, titleLower, faviconHash) {
				matchedProducts[fp.Product.Name] = true

				// 1. 记录产品名
				name := fp.Product.Name
				if fp.Product.Vendor != "" && fp.Product.Vendor != fp.Product.Name {
					name += fmt.Sprintf(" [%s]", fp.Product.Vendor)
				}
				names = append(names, name)

				// 2. 记录匹配原因 (产品: 规则信息)
				reason := fmt.Sprintf("%s (匹配点: %s, 模式: %s)",
					fp.Product.Name, rule.Location, rule.Pattern)
				reasons = append(reasons, reason)

				// 匹配到一个规则即可认为产品匹配成功
				break
			}
		}
	}

	return names, reasons
}

// matchFingerprint 匹配单个指纹的所有规则
func (m *GoSecProbeMatcher) matchFingerprint(fp GoSecProbeFingerprint, headers map[string]string,
	body, bodyLower, title, titleLower string, faviconHash string) bool {

	// 至少匹配一个规则即可
	for _, rule := range fp.Fingerprint.Rules {
		if m.matchRule(rule, headers, body, bodyLower, title, titleLower, faviconHash) {
			return true
		}
	}
	return false
}

// matchRule 匹配单个规则
func (m *GoSecProbeMatcher) matchRule(rule FingerprintRule, headers map[string]string,
	body, bodyLower, title, titleLower string, faviconHash string) bool {

	location := strings.ToLower(rule.Location)
	matchType := strings.ToLower(rule.MatchType)
	pattern := rule.Pattern

	// 如果匹配类型是 hash 相关，优先匹配 faviconHash
	if matchType == "favicon_hash" || matchType == "icon_hash" {
		return m.performMatch(matchType, pattern, faviconHash, faviconHash)
	}

	// 根据location确定匹配目标
	var target string
	var targetLower string

	switch location {
	case "favicon_hash", "icon_hash":
		return m.performMatch(matchType, pattern, faviconHash, faviconHash)
	case "header":
		// 匹配所有header值
		for _, value := range headers {
			if m.performMatch(matchType, pattern, value, value) {
				return true
			}
		}
		return false

	case "body":
		target = body
		targetLower = bodyLower

	case "title":
		target = title
		targetLower = titleLower

	default:
		// 默认匹配body
		target = body
		targetLower = bodyLower
	}

	return m.performMatch(matchType, pattern, target, targetLower)
}

// performMatch 执行具体的匹配
func (m *GoSecProbeMatcher) performMatch(matchType, pattern, target, targetLower string) bool {
	if pattern == "" {
		return false
	}

	cleanPattern := pattern
	isComplexRule := false

	// 预处理 ARL/Goby 规则字符串
	if strings.Contains(pattern, "=") {
		if strings.HasPrefix(pattern, "header=\"") || strings.HasPrefix(pattern, "body=\"") ||
			strings.HasPrefix(pattern, "title=\"") || strings.HasPrefix(pattern, "icon_hash=\"") {
			isComplexRule = true
			start := strings.Index(pattern, "\"")
			end := strings.LastIndex(pattern, "\"")
			if start != -1 && end > start {
				cleanPattern = pattern[start+1 : end]
			}
		}
	}

	if cleanPattern == "" {
		return false
	}

	// 降噪核：过滤掉极其通用的超短关键字（长度 < 4）
	// 排除掉这种类似 "oa", "cms", "wap" 这种会导致大面积误报的规则
	if !isComplexRule && matchType == "keyword" && len(cleanPattern) < 4 {
		return false
	}

	cleanPatternLower := strings.ToLower(cleanPattern)

	switch matchType {
	case "keyword":
		return strings.Contains(targetLower, cleanPatternLower)

	case "regex":
		re, err := regexp.Compile(cleanPattern)
		if err != nil {
			return false
		}
		return re.MatchString(target)

	case "favicon_hash", "hash":
		if target == "" || cleanPattern == "" {
			return false
		}
		// Hash 匹配必须更有特异性，避免短数字序列误命中
		if len(cleanPattern) < 6 {
			return target == cleanPattern
		}
		return strings.Contains(target, cleanPattern)

	case "goby_rule", "arl_rule":
		// 转换来的规则如果解析后依然很短，说明特异性不足，跳过
		if len(cleanPatternLower) < 4 {
			return false
		}
		return strings.Contains(targetLower, cleanPatternLower)

	default:
		if len(cleanPatternLower) < 4 {
			return false
		}
		return strings.Contains(targetLower, cleanPatternLower)
	}
}

// calculateMD5Hash 计算字符串MD5哈希
func calculateMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return fmt.Sprintf("%x", hash)
}

// CalculateFaviconHash 计算favicon哈希 (Shodan mmh3格式)
func CalculateFaviconHash(faviconData []byte) string {
	// 这里可以实现mmh3哈希算法
	// 目前返回MD5作为简化实现
	hash := md5.Sum(faviconData)
	return fmt.Sprintf("%x", hash)
}

// DownloadFavicon 下载并计算favicon哈希
func DownloadFavicon(baseURL string, client *http.Client) (string, error) {
	faviconURL := baseURL + "/favicon.ico"

	resp, err := client.Get(faviconURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("favicon not found: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return CalculateFaviconHash(data), nil
}

// GetMatchedCount 获取匹配到的指纹数量
func (m *GoSecProbeMatcher) GetMatchedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.fingerprints)
}
