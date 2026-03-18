package scanport

import (
	"GoSecProbe/common/log"
	"GoSecProbe/service/common"
	"context"
	"fmt"
	"time"
)

// PortScanService 端口扫描服务，使用纯Go实现的综合扫描器
// 不依赖nmap库，使用goroutine进行高效并发扫描
type PortScanService struct {
	ComprehensiveScanner *ComprehensivePortScanner
}

// NewPortScanService 创建端口扫描服务
// 完全使用自定义Go实现，利用goroutine的并发特性进行快速扫描
func NewPortScanService(timeout time.Duration, concurrency int, enableFingerprint bool) *PortScanService {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	if concurrency == 0 {
		concurrency = 100
	}

	// 指纹库文件路径
	probesFile := "./service/lib/nmap-service-probes.txt"

	// 创建综合扫描器（使用Go原生实现）
	compScanner, err := NewComprehensivePortScanner(
		2*time.Second, // 端口检测超时
		5*time.Second, // 指纹识别超时
		concurrency,   // 并发数
		probesFile,
		enableFingerprint,
	)
	if err != nil {
		log.Info("[错误] 创建综合扫描器失败: %v", err)
		// 即使失败也创建一个基础扫描器，但关闭指纹识别
		compScanner, _ = NewComprehensivePortScanner(
			2*time.Second,
			5*time.Second,
			concurrency,
			"",
			false,
		)
	}

	log.Info("[端口扫描服务] 已启用纯Go实现的综合扫描模式")
	log.Info("  - 端口检测: 使用Go原生TCP连接测试（goroutine并发）")
	log.Info("  - 指纹识别: %v", enableFingerprint)
	if enableFingerprint {
		log.Info("  - 指纹库: nmap-service-probes.txt")
	}
	log.Info("  - 并发数: %d", concurrency)

	return &PortScanService{
		ComprehensiveScanner: compScanner,
	}
}

// PortScanServiceResult 端口扫描服务结果
type PortScanServiceResult struct {
	Target       *common.Target // 目标信息
	ScanResult   *ScanResult    // 扫描结果
	Fingerprints []*Fingerprint // 指纹信息
	Error        error          // 错误信息
}

// ScanTargets 扫描目标字符串（自动解析并扫描）
// 使用纯Go实现，分两步进行：
// 1. 使用goroutine并发探测端口开放状态
// 2. 对开放/过滤端口进行指纹识别
func (s *PortScanService) ScanTargets(ctx context.Context, targetStr string, portRange string) ([]PortScanServiceResult, error) {
	// 解析目标
	log.Info("[端口扫描服务] 开始解析目标: %s", targetStr)
	parser := common.NewTargetParser(true)
	targets, err := parser.ParseTargets(targetStr)
	if err != nil {
		return nil, fmt.Errorf("解析目标失败: %v", err)
	}

	log.Info("[端口扫描服务] 解析完成，共 %d 个目标", len(targets))

	// 解析端口范围
	parsedPortRange, err := ParsePortRange(portRange)
	if err != nil {
		return nil, fmt.Errorf("解析端口范围失败: %v", err)
	}

	log.Info("[端口扫描服务] 端口范围: %s", parsedPortRange)

	// 提取所有需要扫描的IP
	hosts := make([]string, 0)
	targetMap := make(map[string]*common.Target)

	for _, target := range targets {
		ip := target.IP
		if ip == "" {
			ip = target.Host
		}
		if ip != "" {
			hosts = append(hosts, ip)
			targetMap[ip] = target
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("没有可扫描的主机")
	}

	// 使用综合扫描器进行扫描
	log.Info("[端口扫描服务] 开始使用Go并发扫描 %d 个主机", len(hosts))
	compResults := s.ComprehensiveScanner.ScanMultipleHosts(ctx, hosts, parsedPortRange)

	// 转换为服务结果格式
	results := make([]PortScanServiceResult, 0, len(compResults))
	for _, compResult := range compResults {
		scanResult := ConvertToScanResult(compResult)
		result := PortScanServiceResult{
			Target:       targetMap[compResult.IP],
			ScanResult:   scanResult,
			Fingerprints: compResult.Fingerprints,
			Error:        compResult.Error,
		}
		results = append(results, result)
	}

	// 统计
	totalOpenPorts := 0
	hostsWithPorts := 0
	for _, r := range results {
		if r.ScanResult != nil && r.ScanResult.OpenPorts > 0 {
			totalOpenPorts += r.ScanResult.OpenPorts
			hostsWithPorts++
		}
	}

	log.Info("[端口扫描服务] 扫描完成，%d/%d 主机有开放端口，共发现 %d 个开放端口",
		hostsWithPorts, len(results), totalOpenPorts)

	return results, nil
}

// QuickPortScan 快速端口扫描（使用默认参数）
func QuickPortScan(ctx context.Context, targetStr string, portRange string) ([]PortScanServiceResult, error) {
	service := NewPortScanService(
		5*time.Minute, // 5分钟超时
		100,           // 100并发
		true,          // 启用指纹识别
	)
	return service.ScanTargets(ctx, targetStr, portRange)
}

// GetOpenPortsFromResults 获取所有开放端口的IP列表
func GetOpenPortsFromResults(results []PortScanServiceResult) []string {
	ips := make([]string, 0)
	for _, result := range results {
		if result.ScanResult != nil && result.ScanResult.OpenPorts > 0 {
			if result.Target.IP != "" {
				ips = append(ips, result.Target.IP)
			} else if result.Target.Host != "" {
				ips = append(ips, result.Target.Host)
			}
		}
	}
	return ips
}

// GetPortSummary 获取端口扫描摘要
func GetPortSummary(results []PortScanServiceResult) map[string]interface{} {
	summary := map[string]interface{}{
		"total_hosts":      len(results),
		"hosts_with_ports": 0,
		"total_open_ports": 0,
		"services":         make(map[string]int),
		"products":         make(map[string]int),
		"common_ports":     make(map[uint16]int),
	}

	services := summary["services"].(map[string]int)
	products := summary["products"].(map[string]int)
	commonPorts := summary["common_ports"].(map[uint16]int)

	for _, result := range results {
		if result.ScanResult == nil {
			continue
		}

		if result.ScanResult.OpenPorts > 0 {
			summary["hosts_with_ports"] = summary["hosts_with_ports"].(int) + 1
			summary["total_open_ports"] = summary["total_open_ports"].(int) + result.ScanResult.OpenPorts
		}

		for _, port := range result.ScanResult.Ports {
			// 统计服务
			if port.Service.Name != "" {
				services[port.Service.Name]++
			}

			// 统计产品
			if port.Service.Product != "" {
				products[port.Service.Product]++
			}

			// 统计常见端口
			commonPorts[port.Port]++
		}
	}

	return summary
}

// FilterResultsByService 按服务过滤结果
func FilterResultsByService(results []PortScanServiceResult, service string) []PortScanServiceResult {
	filtered := make([]PortScanServiceResult, 0)

	for _, result := range results {
		if result.ScanResult == nil {
			continue
		}

		hasService := false
		for _, port := range result.ScanResult.Ports {
			if port.Service.Name == service {
				hasService = true
				break
			}
		}

		if hasService {
			filtered = append(filtered, result)
		}
	}

	return filtered
}

// FilterResultsByPort 按端口号过滤结果
func FilterResultsByPort(results []PortScanServiceResult, port uint16) []PortScanServiceResult {
	filtered := make([]PortScanServiceResult, 0)

	for _, result := range results {
		if result.ScanResult == nil {
			continue
		}

		hasPort := false
		for _, p := range result.ScanResult.Ports {
			if p.Port == port {
				hasPort = true
				break
			}
		}

		if hasPort {
			filtered = append(filtered, result)
		}
	}

	return filtered
}

// GetServiceDistribution 获取服务分布统计
func GetServiceDistribution(results []PortScanServiceResult) map[string][]string {
	distribution := make(map[string][]string)

	for _, result := range results {
		if result.ScanResult == nil {
			continue
		}

		ip := result.Target.IP
		if ip == "" {
			ip = result.Target.Host
		}

		for _, port := range result.ScanResult.Ports {
			if port.Service.Name != "" {
				key := fmt.Sprintf("%s:%d", port.Service.Name, port.Port)
				distribution[key] = append(distribution[key], ip)
			}
		}
	}

	return distribution
}
