package scanhost

import (
	"GoSecProbe/common/log"
	"GoSecProbe/service/common"
	"context"
	"fmt"
	"time"
)

// ScanService 扫描服务，整合目标解析和主机扫描
type ScanService struct {
	Parser  *common.TargetParser
	Scanner *HostScanner
}

// NewScanService 创建扫描服务
func NewScanService(enableDNS bool, timeout time.Duration, concurrency int) *ScanService {
	return &ScanService{
		Parser:  common.NewTargetParser(enableDNS),
		Scanner: NewHostScanner(timeout, concurrency),
	}
}

// ScanResult 扫描结果
type ScanResult struct {
	Target    *common.Target // 目标信息
	HostAlive bool           // 主机是否存活
	Latency   time.Duration  // 延迟
	Error     error          // 错误信息
}

// ScanTargets 扫描目标字符串（自动解析并扫描）
func (s *ScanService) ScanTargets(ctx context.Context, targetStr string) ([]ScanResult, error) {
	// 解析目标
	log.Info("[主机扫描] 开始解析目标: %s", targetStr)
	targets, err := s.Parser.ParseTargets(targetStr)
	if err != nil {
		return nil, fmt.Errorf("解析目标失败: %v", err)
	}

	log.Info("[主机扫描] 解析完成，共 %d 个目标", len(targets))

	// 提取所有需要扫描的IP
	hosts := make([]string, 0)
	for _, target := range targets {
		if target.IP != "" {
			hosts = append(hosts, target.IP)
		} else if target.Host != "" {
			hosts = append(hosts, target.Host)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("没有可扫描的主机")
	}

	// 执行主机扫描
	log.Info("[主机扫描] 开始扫描 %d 个主机", len(hosts))
	hostResults := s.Scanner.ScanHosts(ctx, hosts)

	// 合并结果
	results := make([]ScanResult, 0)
	hostResultMap := make(map[string]HostResult)

	for _, hr := range hostResults {
		hostResultMap[hr.IP] = hr
	}

	for _, target := range targets {
		result := ScanResult{
			Target: target,
		}

		// 查找对应的主机扫描结果
		host := target.IP
		if host == "" {
			host = target.Host
		}

		if hr, ok := hostResultMap[host]; ok {
			result.HostAlive = hr.IsAlive
			result.Latency = hr.Latency
			result.Error = hr.Error
		}

		results = append(results, result)
	}

	// 统计
	aliveCount := 0
	for _, r := range results {
		if r.HostAlive {
			aliveCount++
		}
	}
	log.Info("[主机扫描] 扫描完成，%d/%d 主机存活", aliveCount, len(results))

	return results, nil
}

// GetAliveTargets 获取存活的目标
func GetAliveTargets(results []ScanResult) []*common.Target {
	aliveTargets := make([]*common.Target, 0)
	for _, result := range results {
		if result.HostAlive {
			aliveTargets = append(aliveTargets, result.Target)
		}
	}
	return aliveTargets
}

// GetAliveIPsFromResults 获取存活主机的IP列表
func GetAliveIPsFromResults(results []ScanResult) []string {
	ips := make([]string, 0)
	for _, result := range results {
		if result.HostAlive {
			if result.Target.IP != "" {
				ips = append(ips, result.Target.IP)
			} else if result.Target.Host != "" {
				ips = append(ips, result.Target.Host)
			}
		}
	}
	return ips
}

// QuickScan 快速扫描（使用默认参数）
func QuickScan(ctx context.Context, targetStr string) ([]ScanResult, error) {
	service := NewScanService(
		true,          // 启用DNS
		3*time.Second, // 3秒超时
		50,            // 50并发
	)
	return service.ScanTargets(ctx, targetStr)
}
