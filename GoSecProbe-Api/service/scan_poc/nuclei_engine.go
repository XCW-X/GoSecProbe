package service

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// NucleiEngine nuclei 引擎封装
type NucleiEngine struct {
	engine       *nuclei.ThreadSafeNucleiEngine
	mu           sync.RWMutex
	templatesDir string
	results      []VerifyResult
	ctx          context.Context
	cancel       context.CancelFunc
}

// VerifyResult POC 验证结果
type VerifyResult struct {
	TemplateID    string                 `json:"template_id"`
	TemplateName  string                 `json:"template_name"`
	Target        string                 `json:"target"`
	Matched       bool                   `json:"matched"`
	Severity      string                 `json:"severity"`
	Description   string                 `json:"description"`
	MatchedAt     string                 `json:"matched_at,omitempty"`
	Request       string                 `json:"request,omitempty"`
	Response      string                 `json:"response,omitempty"`
	ExtractedData map[string]interface{} `json:"extracted_data,omitempty"`
	Error         string                 `json:"error,omitempty"`
	ID            int64                  `json:"id,omitempty"` // 数据库ID
	Timestamp     time.Time              `json:"timestamp"`
}

// NewNucleiEngine 创建新的 nuclei 引擎实例
func NewNucleiEngine(templatesDir string) (*NucleiEngine, error) {
	if templatesDir == "" {
		// 默认使用项目中的 nuclei-templates 目录
		templatesDir = filepath.Join("service", "lib", "nuclei-templates")
	}

	// 检查模板目录是否存在
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("templates directory not found: %s", templatesDir)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &NucleiEngine{
		templatesDir: templatesDir,
		results:      make([]VerifyResult, 0),
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// VerifyWithTemplates 使用指定的模板验证目标
func (ne *NucleiEngine) VerifyWithTemplates(target string, templateIDs []string) ([]VerifyResult, error) {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	// 重置结果
	ne.results = make([]VerifyResult, 0)

	// 查找模板文件路径
	templatePaths, err := ne.findTemplateFiles(templateIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to find template files: %v", err)
	}

	if len(templatePaths) == 0 {
		return nil, fmt.Errorf("no template files found for given IDs")
	}

	log.Info("[NucleiEngine] Starting verification for target: %s with %d templates", target, len(templatePaths))

	// 获取 Interactsh 选项
	interactOpts := ne.getInteractshOpts()

	// 创建 nuclei 引擎选项
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: templatePaths,
		}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           10, // 模板并发数
			HostConcurrency:               3,  // 主机并发数
			HeadlessHostConcurrency:       1,  // 无头浏览器主机并发数
			HeadlessTemplateConcurrency:   1,  // 无头浏览器模板并发数
			JavascriptTemplateConcurrency: 1,  // JavaScript 模板并发数
			TemplatePayloadConcurrency:    25, // Payload 并发数
			ProbeConcurrency:              50, // HTTP 探测并发数
		}),
		nuclei.WithInteractshOptions(interactOpts),
		nuclei.DisableUpdateCheck(), // 禁用自动模板下载和更新检查
	}

	// 创建 nuclei 引擎实例
	engine, err := nuclei.NewThreadSafeNucleiEngineCtx(ne.ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create nuclei engine: %v", err)
	}
	defer engine.Close()

	ne.engine = engine

	// 设置结果回调函数
	matchCount := 0
	engine.GlobalResultCallback(func(event *output.ResultEvent) {
		result := ne.convertResultEvent(event, target)
		ne.results = append(ne.results, result)
		matchCount++
		log.Info("[NucleiEngine] ✅ Match #%d found: %s on %s (severity: %s)",
			matchCount, event.TemplateID, target, event.Info.SeverityHolder.Severity)
	})

	log.Info("[NucleiEngine] 🚀 Starting nuclei scan against %s...", target)

	// 执行扫描
	err = engine.ExecuteNucleiWithOpts([]string{target})
	if err != nil {
		return nil, fmt.Errorf("execution failed: %v", err)
	}

	log.Info("[NucleiEngine] ✔ Scan completed. Matches: %d, Total results: %d",
		matchCount, len(ne.results))

	// 如果没有匹配结果，为每个模板创建一个"未匹配"的结果
	if len(ne.results) == 0 {
		for _, templateID := range templateIDs {
			ne.results = append(ne.results, VerifyResult{
				TemplateID: templateID,
				Target:     target,
				Matched:    false,
				Severity:   "info",
				Timestamp:  time.Now(),
			})
		}
	}

	log.Info("[NucleiEngine] Verification completed: %d results", len(ne.results))
	return ne.results, nil
}

// findTemplateFiles 根据模板 ID 查找模板文件路径
func (ne *NucleiEngine) findTemplateFiles(templateIDs []string) ([]string, error) {
	var templatePaths []string
	templateMap := make(map[string]bool)

	for _, id := range templateIDs {
		templateMap[id] = true
	}

	// 遍历 templates 目录查找匹配的模板文件
	err := filepath.Walk(ne.templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理 .yaml 文件
		ext := filepath.Ext(path)
		if info.IsDir() || (ext != ".yaml" && ext != ".yml") {
			return nil
		}

		// 检查文件名是否包含任何模板 ID
		relPath, _ := filepath.Rel(ne.templatesDir, path)
		for templateID := range templateMap {
			// 检查文件路径或文件名是否包含模板 ID
			if containsTemplateID(relPath, templateID) || containsTemplateID(filepath.Base(path), templateID) {
				templatePaths = append(templatePaths, path)
				delete(templateMap, templateID)
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return templatePaths, nil
}

// containsTemplateID 检查路径是否包含模板 ID
func containsTemplateID(path, templateID string) bool {
	// 简单的字符串匹配，可以根据需要改进
	return filepath.Base(path) == templateID+".yaml" ||
		filepath.Base(path) == templateID+".yml" ||
		containsString(path, templateID)
}

// containsString 检查字符串是否包含子串（不区分大小写）
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr))
}

// convertResultEvent 将 nuclei 的 ResultEvent 转换为 VerifyResult
func (ne *NucleiEngine) convertResultEvent(event *output.ResultEvent, target string) VerifyResult {
	result := VerifyResult{
		TemplateID:   event.TemplateID,
		TemplateName: event.Info.Name,
		Target:       target,
		Matched:      event.Matched != "",                         // 使用 nuclei 返回的匹配状态
		Severity:     event.Info.SeverityHolder.Severity.String(), // 使用String()方法
		Description:  event.Info.Description,
		Timestamp:    time.Now(),
	}

	// MatchedAt 字段在 nuclei v3 中可能不存在，使用 Host 或 URL 替代
	if event.Host != "" {
		result.MatchedAt = event.Host
	} else if event.URL != "" {
		result.MatchedAt = event.URL
	}

	if event.Request != "" {
		result.Request = event.Request
	}

	if event.Response != "" {
		result.Response = event.Response
	}

	// 提取数据
	if len(event.ExtractedResults) > 0 {
		result.ExtractedData = make(map[string]interface{})
		for i, extracted := range event.ExtractedResults {
			result.ExtractedData[fmt.Sprintf("extracted_%d", i)] = extracted
		}
	}

	return result
}

// getInteractshOpts 获取并在控制台输出 Interactsh 配置选项
func (ne *NucleiEngine) getInteractshOpts() nuclei.InteractshOpts {
	var interactshURL string

	// 读取系统配置，获取自定义 DNSLog 域名
	systemSettings, err := mysql.GetSettings()
	if err != nil {
		fmt.Printf("[DEBUG] mysql.GetSettings error: %v\n", err)
		interactshURL = "oast.live"
		log.Info("[NucleiEngine] Using default Interactsh server (due to db error): %s", interactshURL)
	} else if systemSettings.ReverseDnslogDomain != "" {
		// 使用用户配置的 DNSLog 域名
		interactshURL = systemSettings.ReverseDnslogDomain
		// 如果没有协议前缀，补充 https://
		if !strings.HasPrefix(interactshURL, "http") {
			interactshURL = "https://" + interactshURL
		}
		fmt.Printf("[DEBUG] Custom DNSLog found: %s\n", interactshURL)
		log.Info("[NucleiEngine] Using custom Interactsh server: %s", interactshURL)
	} else {
		// 使用默认的 oast.live
		interactshURL = "oast.live"
		fmt.Printf("[DEBUG] No custom DNSLog, using default\n")
		log.Info("[NucleiEngine] Using default Interactsh server: %s", interactshURL)
	}

	return nuclei.InteractshOpts{
		ServerURL:      interactshURL,
		CacheSize:      5000,             // 必须 > 0，否则会导致 gcache panic
		Eviction:       60 * time.Second, // 缓存过期时间
		PollDuration:   5 * time.Second,  // 轮询间隔
		CooldownPeriod: 5 * time.Second,  // 冷却时间
	}
}

// VerifyWithTemplatePaths 使用指定的模板文件路径验证目标
func (ne *NucleiEngine) VerifyWithTemplatePaths(target string, templatePaths []string, pocs []*mysql.PocTemplate, variables map[string]string) ([]VerifyResult, error) {
	ne.mu.Lock()
	defer ne.mu.Unlock()

	// 重置结果
	ne.results = make([]VerifyResult, 0)

	if len(templatePaths) == 0 {
		return nil, fmt.Errorf("no template files provided")
	}

	// 构建完整的模板文件路径
	fullPaths := make([]string, 0, len(templatePaths))
	for i, path := range templatePaths {
		// 如果是相对路径，拼接基础目录
		fullPath := path
		if !filepath.IsAbs(path) {
			fullPath = filepath.Join(ne.templatesDir, path)
		}

		// 检查文件是否存在
		fileInfo, err := os.Stat(fullPath)
		if err != nil {
			log.Warn("[NucleiEngine] Warning: Template file not found: %s (error: %v)", fullPath, err)
			continue
		}

		log.Info("[NucleiEngine] Template %d: %s (size: %d bytes)", i+1, fullPath, fileInfo.Size())

		// 读取文件前几行用于调试
		content, err := os.ReadFile(fullPath)
		if err == nil && len(content) > 0 {
			lines := strings.Split(string(content), "\n")
			preview := ""
			for j := 0; j < 5 && j < len(lines); j++ {
				preview += lines[j] + "\n"
			}
			log.Info("[NucleiEngine] Template preview:\n%s", preview)
		}

		fullPaths = append(fullPaths, fullPath)
	}

	if len(fullPaths) == 0 {
		return nil, fmt.Errorf("no valid template files found")
	}

	log.Info("[NucleiEngine] Starting verification for target: %s with %d templates", target, len(fullPaths))

	// 获取 Interactsh 选项
	interactOpts := ne.getInteractshOpts()

	// 创建共享 logger，防止 nuclei 内部 store.logger 为 nil 时 panic
	sharedLogger := &gologger.Logger{}
	sharedLogger.SetMaxLevel(levels.LevelWarning)
	sharedLogger.SetFormatter(formatter.NewCLI(true))
	sharedLogger.SetWriter(writer.NewCLI())

	// 创建 nuclei 引擎选项
	opts := []nuclei.NucleiSDKOptions{
		nuclei.WithLogger(sharedLogger), // 注入 logger，避免 nil pointer panic
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: fullPaths,
		}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           10, // 模板并发数
			HostConcurrency:               3,  // 主机并发数
			HeadlessHostConcurrency:       1,  // 无头浏览器主机并发数
			HeadlessTemplateConcurrency:   1,  // 无头浏览器模板并发数
			JavascriptTemplateConcurrency: 1,  // JavaScript 模板并发数
			TemplatePayloadConcurrency:    25, // Payload 并发数
			ProbeConcurrency:              50, // HTTP 探测并发数
		}),
		nuclei.WithInteractshOptions(interactOpts),
		nuclei.EnableMatcherStatus(), // 启用匹配器状态
		// 自定义 Verbosity 选项，绕过 ThreadSafe 检查
		func(e *nuclei.NucleiEngine) error {
			e.Options().Debug = true
			e.Options().DebugRequests = true
			e.Options().DebugResponse = true
			return nil
		},
		nuclei.DisableUpdateCheck(), // 禁用自动模板下载和更新检查
	}

	// 添加自定义变量
	if len(variables) > 0 {
		var vars []string
		for k, v := range variables {
			vars = append(vars, fmt.Sprintf("%s=%s", k, v))
		}
		opts = append(opts, nuclei.WithVars(vars))
	}

	// 创建 nuclei 引擎实例
	engine, err := nuclei.NewThreadSafeNucleiEngineCtx(ne.ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create nuclei engine: %v", err)
	}
	defer engine.Close()

	ne.engine = engine

	// 创建 POC 映射（通过模板ID）
	pocMap := make(map[string]*mysql.PocTemplate)
	for _, poc := range pocs {
		pocMap[poc.TemplateID] = poc
	}

	// 设置结果回调函数
	// 设置结果回调函数
	engine.GlobalResultCallback(func(event *output.ResultEvent) {
		result := ne.convertResultEvent(event, target)

		// 补充 POC 信息
		if poc, exists := pocMap[event.TemplateID]; exists {
			result.TemplateName = poc.Name
			if result.Severity == "" {
				result.Severity = poc.Severity
			}
			if result.Description == "" {
				result.Description = poc.Description
			}
		}

		ne.results = append(ne.results, result)
		if result.Matched {
			log.Info("[NucleiEngine] Match found: %s on %s (severity: %s)", event.TemplateID, target, event.Info.SeverityHolder.Severity)
		} else {
			log.Info("[NucleiEngine] Scan finished (no match): %s on %s", event.TemplateID, target)
		}
	})

	// 执行扫描
	err = engine.ExecuteNucleiWithOpts([]string{target})
	if err != nil {
		return nil, fmt.Errorf("execution failed: %v", err)
	}

	// 聚合相同 TemplateID 的结果
	type AggregatedData struct {
		Result    VerifyResult
		Requests  []string
		Responses []string
	}
	aggregatedMap := make(map[string]*AggregatedData)

	// 按顺序处理所有原始结果
	for _, result := range ne.results {
		if data, exists := aggregatedMap[result.TemplateID]; exists {
			// 只有当现有结果没有匹配，而新结果匹配时，才更新匹配状态和Severity
			if !data.Result.Matched && result.Matched {
				data.Result.Matched = true
				data.Result.Severity = result.Severity
				data.Result.MatchedAt = result.MatchedAt
				// 如果是匹配的结果，优先使用它的 TemplateName 等信息
				data.Result.TemplateName = result.TemplateName
			}

			// 收集 Request 和 Response (带去重和空值处理)
			req := result.Request
			res := result.Response

			// 简单的去重：如果当前请求响应对与最后加入的一致，则跳过
			isDuplicate := false
			if len(data.Requests) > 0 {
				lastReq := data.Requests[len(data.Requests)-1]
				lastRes := data.Responses[len(data.Responses)-1]
				// 对比时去除首尾空白可能更稳健，但完全相等也行
				if lastReq == req && lastRes == res {
					isDuplicate = true
				}
			}

			if !isDuplicate {
				// 只有当至少有一个不为空时才添加，确保 Request 和 Response 数组长度同步
				if req != "" || res != "" {
					data.Requests = append(data.Requests, req)
					data.Responses = append(data.Responses, res)
				}
			}

			// 合并 ExtractedData
			if result.ExtractedData != nil {
				if data.Result.ExtractedData == nil {
					data.Result.ExtractedData = make(map[string]interface{})
				}
				for k, v := range result.ExtractedData {
					data.Result.ExtractedData[k] = v
				}
			}

			// 合并 Error
			if result.Error != "" && !strings.Contains(data.Result.Error, result.Error) {
				if data.Result.Error != "" {
					data.Result.Error += "; " + result.Error
				} else {
					data.Result.Error = result.Error
				}
			}
		} else {
			// 初始化新的聚合数据
			data := &AggregatedData{
				Result:    result,
				Requests:  make([]string, 0),
				Responses: make([]string, 0),
			}
			// 添加第一条记录
			if result.Request != "" || result.Response != "" {
				data.Requests = append(data.Requests, result.Request)
				data.Responses = append(data.Responses, result.Response)
			}
			aggregatedMap[result.TemplateID] = data
		}
	}

	var finalResults []VerifyResult

	// 将聚合后的 Map 转换回 Slice，并处理 JSON 序列化
	returnedTemplates := make(map[string]bool)
	for _, poc := range pocs {
		if data, exists := aggregatedMap[poc.TemplateID]; exists {
			// 如果有多个请求/响应，序列化为 JSON 数组
			if len(data.Requests) > 1 || len(data.Responses) > 1 {
				reqJSON, _ := json.Marshal(data.Requests)
				resJSON, _ := json.Marshal(data.Responses)
				data.Result.Request = string(reqJSON)
				data.Result.Response = string(resJSON)
			}

			finalResults = append(finalResults, data.Result)
			returnedTemplates[poc.TemplateID] = true
		}
	}

	// 为未返回任何结果的模板创建占位结果
	for _, poc := range pocs {
		if !returnedTemplates[poc.TemplateID] {
			finalResults = append(finalResults, VerifyResult{
				TemplateID:   poc.TemplateID,
				TemplateName: poc.Name,
				Target:       target,
				Matched:      false,
				Severity:     poc.Severity,
				Description:  poc.Description,
				Timestamp:    time.Now(),
				Error:        "No response from scanner",
			})
		}
	}

	log.Info("[NucleiEngine] Verification completed: %d aggregated results", len(finalResults))
	return finalResults, nil
}

// Close 关闭引擎
func (ne *NucleiEngine) Close() {
	ne.cancel()
	if ne.engine != nil {
		ne.engine.Close()
	}
}
