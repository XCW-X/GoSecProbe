package service

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"GoSecProbe/service/common"
	"fmt"
	"strings"
	"sync"
)

// PocVerifier POC 验证器
type PocVerifier struct {
	engine *NucleiEngine
	mu     sync.Mutex
}

// NewPocVerifier 创建 POC 验证器
func NewPocVerifier(templatesDir string) (*PocVerifier, error) {
	engine, err := NewNucleiEngine(templatesDir)
	if err != nil {
		return nil, err
	}

	return &PocVerifier{
		engine: engine,
	}, nil
}

// VerifyRequest POC 验证请求
type VerifyRequest struct {
	Target    string            `json:"target,omitempty"`
	Targets   []string          `json:"targets,omitempty"`
	PocIDs    []int             `json:"poc_ids" binding:"required"`
	ResultID  int64             `json:"result_id,omitempty"` // 用于重新验证时更新现有记录
	Threads   int               `json:"threads,omitempty"`
	Timeout   int               `json:"timeout,omitempty"`
	Variables map[string]string `json:"variables,omitempty"` // 模板变量 (e.g. username, password)
}

// VerifyResponse POC 验证响应
type VerifyResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message"`
	Results []VerifyResult `json:"results"`
	Total   int            `json:"total"`
}

// Verify 执行 POC 验证
func (pv *PocVerifier) Verify(req VerifyRequest) (*VerifyResponse, error) {
	pv.mu.Lock()
	defer pv.mu.Unlock()

	log.Info("[PocVerifier] Starting verification for target: %s with %d POCs", req.Target, len(req.PocIDs))

	// 使用 TargetParser 处理目标地址
	parser := common.NewTargetParser(false) // 不需要DNS解析
	parsedTarget, err := parser.ParseTarget(req.Target)
	if err != nil {
		log.Error("[PocVerifier] Failed to parse target: %v", err)
		return &VerifyResponse{
			Success: false,
			Message: fmt.Sprintf("无效的目标地址: %v", err),
			Results: []VerifyResult{},
			Total:   0,
		}, err
	}

	// 构建完整的目标URL
	// nuclei 需要完整的 URL (http:// 或 https://)
	target := req.Target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// 默认使用 http://
		target = "http://" + target
	}

	log.Info("[PocVerifier] Parsed target: %s -> %s (IP: %s)", req.Target, target, parsedTarget.IP)

	// 查询 POC 模板信息并收集模板文件路径
	var templatePaths []string
	var pocs []*mysql.PocTemplate

	for _, pocID := range req.PocIDs {
		poc, err := mysql.GetPocTemplateByID(int64(pocID))
		if err != nil {
			log.Warn("[PocVerifier] Warning: Failed to get POC %d: %v", pocID, err)
			continue
		}

		if poc == nil {
			log.Warn("[PocVerifier] Warning: POC %d not found", pocID)
			continue
		}

		// 使用数据库中的 file_path
		if poc.FilePath == "" {
			log.Warn("[PocVerifier] Warning: POC %d has no file_path", pocID)
			continue
		}

		templatePaths = append(templatePaths, poc.FilePath)
		pocs = append(pocs, poc)
	}

	if len(templatePaths) == 0 {
		return &VerifyResponse{
			Success: false,
			Message: "No valid POC templates found",
			Results: []VerifyResult{},
			Total:   0,
		}, nil
	}

	// 使用 nuclei 引擎执行验证（传递文件路径和格式化后的目标URL）
	results, err := pv.engine.VerifyWithTemplatePaths(target, templatePaths, pocs, req.Variables)
	if err != nil {
		log.Error("[PocVerifier] Verification failed: %v", err)
		return &VerifyResponse{
			Success: false,
			Message: fmt.Sprintf("Verification failed: %v", err),
			Results: []VerifyResult{},
			Total:   0,
		}, err
	}

	log.Info("[PocVerifier] Verification completed: %d results (matched: %d)",
		len(results), countMatched(results))

	return &VerifyResponse{
		Success: true,
		Message: "Verification completed successfully",
		Results: results,
		Total:   len(results),
	}, nil
}

// countMatched 统计匹配的结果数量
func countMatched(results []VerifyResult) int {
	count := 0
	for _, r := range results {
		if r.Matched {
			count++
		}
	}
	return count
}

// Close 关闭验证器
func (pv *PocVerifier) Close() {
	if pv.engine != nil {
		pv.engine.Close()
	}
}
