package scanport

import (
	"GoSecProbe/common/log"
	"GoSecProbe/service/common"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortDetector 端口开放性检测器
type PortDetector struct {
	Timeout     time.Duration
	Concurrency int
}

// NewPortDetector 创建端口检测器
func NewPortDetector(timeout time.Duration, concurrency int) *PortDetector {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	if concurrency == 0 {
		concurrency = 100
	}
	return &PortDetector{
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

// OpenPort 开放端口信息
type OpenPort struct {
	IP       string
	Port     uint16
	Protocol string
	State    string
}

// DetectOpenPorts 检测指定IP的开放端口
func (d *PortDetector) DetectOpenPorts(ctx context.Context, ip string, ports []uint16) []OpenPort {
	openPorts := make([]OpenPort, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, d.Concurrency)

	for _, port := range ports {
		wg.Add(1)
		go func(p uint16) {
			defer wg.Done()

			// 控制并发
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				return
			default:
			}

			if d.isPortOpen(ctx, ip, p) {
				mu.Lock()
				openPorts = append(openPorts, OpenPort{
					IP:       ip,
					Port:     p,
					Protocol: "tcp",
					State:    "open",
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// isPortOpen 检测单个端口是否开放
func (d *PortDetector) isPortOpen(ctx context.Context, ip string, port uint16) bool {
	address := fmt.Sprintf("%s:%d", ip, port)

	dialer := &net.Dialer{
		Timeout: d.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// parsePortList 解析端口列表字符串为端口数组
func parsePortList(portRange string) ([]uint16, error) {
	ports := make([]uint16, 0)
	parts := strings.Split(portRange, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 范围格式
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围格式: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil || start < 1 || start > 65535 {
				return nil, fmt.Errorf("无效的起始端口: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil || end < 1 || end > 65535 {
				return nil, fmt.Errorf("无效的结束端口: %s", rangeParts[1])
			}

			if start > end {
				return nil, fmt.Errorf("起始端口不能大于结束端口: %s", part)
			}

			for i := start; i <= end; i++ {
				ports = append(ports, uint16(i))
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("无效的端口号: %s", part)
			}
			ports = append(ports, uint16(port))
		}
	}

	return ports, nil
}

// ComprehensivePortScanner 综合端口扫描器（包含开放性检测和指纹识别）
type ComprehensivePortScanner struct {
	detector           *PortDetector
	fingerprintScanner *FingerprintScanner
	enableFingerprint  bool
	Tracker            *common.ProgressTracker // 进度跟踪器
}

// NewComprehensivePortScanner 创建综合端口扫描器
func NewComprehensivePortScanner(
	detectTimeout time.Duration,
	fingerprintTimeout time.Duration,
	concurrency int,
	probesFile string,
	enableFingerprint bool,
) (*ComprehensivePortScanner, error) {

	detector := NewPortDetector(detectTimeout, concurrency)

	var fingerprintScanner *FingerprintScanner
	var err error

	if enableFingerprint {
		fingerprintScanner, err = NewFingerprintScanner(fingerprintTimeout, probesFile)
		if err != nil {
			log.Info("[警告] 创建指纹扫描器失败: %v, 将不进行指纹识别", err)
			enableFingerprint = false
		}
	}

	return &ComprehensivePortScanner{
		detector:           detector,
		fingerprintScanner: fingerprintScanner,
		enableFingerprint:  enableFingerprint,
	}, nil
}

// ComprehensiveResult 综合扫描结果
type ComprehensiveResult struct {
	IP                string         // IP地址
	TotalPortsScanned int            // 扫描的总端口数
	OpenPorts         []OpenPort     // 开放端口列表
	Fingerprints      []*Fingerprint // 指纹信息列表
	ScanDuration      time.Duration  // 扫描耗时
	Error             error          // 错误信息
}

// ScanHost 综合扫描单个主机
func (c *ComprehensivePortScanner) ScanHost(ctx context.Context, ip string, portRange string) (*ComprehensiveResult, error) {
	startTime := time.Now()

	log.Info("[综合扫描] 开始扫描 %s，端口范围: %s", ip, portRange)

	// 第一步：解析端口范围
	normalizedRange, err := ParsePortRange(portRange)
	if err != nil {
		return nil, fmt.Errorf("解析端口范围失败: %v", err)
	}

	ports, err := parsePortList(normalizedRange)
	if err != nil {
		return nil, fmt.Errorf("解析端口列表失败: %v", err)
	}

	result := &ComprehensiveResult{
		IP:                ip,
		TotalPortsScanned: len(ports),
		OpenPorts:         make([]OpenPort, 0),
		Fingerprints:      make([]*Fingerprint, 0),
	}

	// 第二步：检测开放端口
	log.Info("[综合扫描] %s 开始检测 %d 个端口的开放状态", ip, len(ports))
	openPorts := c.detector.DetectOpenPorts(ctx, ip, ports)
	result.OpenPorts = openPorts

	log.Info("[综合扫描] %s 发现 %d 个开放端口", ip, len(openPorts))

	// 第三步：对开放端口进行指纹识别
	if c.enableFingerprint && len(openPorts) > 0 {
		log.Info("[综合扫描] %s 开始对 %d 个开放端口进行指纹识别", ip, len(openPorts))

		fingerprints := make([]*Fingerprint, 0, len(openPorts))
		var wg sync.WaitGroup
		var mu sync.Mutex
		semaphore := make(chan struct{}, 10) // 限制指纹识别并发数

		for _, op := range openPorts {
			wg.Add(1)
			go func(openPort OpenPort) {
				defer wg.Done()

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				// 检查上下文是否已取消
				select {
				case <-ctx.Done():
					return
				default:
				}

				fp, err := c.fingerprintScanner.FingerprintPort(ctx, openPort.IP, openPort.Port, openPort.Protocol)
				if err != nil {
					log.Info("[综合扫描] %s:%d 指纹识别失败: %v", openPort.IP, openPort.Port, err)
					// 识别失败，直接标记为 unknown
					fp = &Fingerprint{
						IP:         openPort.IP,
						Port:       openPort.Port,
						Protocol:   openPort.Protocol,
						Service:    "unknown",
						Confidence: 0,
						Method:     "识别失败",
					}
				}

				mu.Lock()
				fingerprints = append(fingerprints, fp)
				mu.Unlock()

				if fp.Service != "" && fp.Service != "unknown" {
					log.Info("[综合扫描] %s:%d 识别为: %s %s %s (置信度: %d, 方法: %s)",
						openPort.IP, openPort.Port, fp.Service, fp.Product, fp.Version, fp.Confidence, fp.Method)
				}
			}(op)
		}

		wg.Wait()
		result.Fingerprints = fingerprints
	}

	result.ScanDuration = time.Since(startTime)

	log.Info("[综合扫描] 完成 %s: 开放端口 %d/%d, 耗时 %v",
		ip, len(result.OpenPorts), result.TotalPortsScanned, result.ScanDuration)

	return result, nil
}

// ScanMultipleHosts 批量扫描多个主机
func (c *ComprehensivePortScanner) ScanMultipleHosts(ctx context.Context, ips []string, portRange string) []*ComprehensiveResult {
	results := make([]*ComprehensiveResult, len(ips))
	var wg sync.WaitGroup

	// 设置总目标数
	if c.Tracker != nil {
		c.Tracker.SetTotal(len(ips))
	}

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, target string) {
			defer wg.Done()

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				results[index] = &ComprehensiveResult{
					IP:    target,
					Error: ctx.Err(),
				}
				return
			default:
			}

			result, err := c.ScanHost(ctx, target, portRange)
			if err != nil {
				results[index] = &ComprehensiveResult{
					IP:    target,
					Error: err,
				}
			} else {
				results[index] = result
			}

			// ✨ 实时报告进度
			if c.Tracker != nil {
				found := result != nil && len(result.OpenPorts) > 0
				c.Tracker.ReportTargetScanned(target, found)
			}
		}(i, ip)
	}

	wg.Wait()
	return results
}

// ConvertToScanResult 将综合扫描结果转换为标准扫描结果格式
func ConvertToScanResult(compResult *ComprehensiveResult) *ScanResult {
	scanResult := &ScanResult{
		IP:           compResult.IP,
		Ports:        make([]PortResult, 0, len(compResult.OpenPorts)),
		TotalPorts:   compResult.TotalPortsScanned,
		OpenPorts:    len(compResult.OpenPorts),
		ScanDuration: compResult.ScanDuration,
		Error:        compResult.Error,
	}

	// 创建指纹映射以便快速查找
	fingerprintMap := make(map[string]*Fingerprint)
	for _, fp := range compResult.Fingerprints {
		key := fmt.Sprintf("%s:%d", fp.IP, fp.Port)
		fingerprintMap[key] = fp
	}

	// 转换开放端口信息
	for _, op := range compResult.OpenPorts {
		portResult := PortResult{
			IP:       op.IP,
			Port:     op.Port,
			Protocol: op.Protocol,
			State:    op.State,
			Service: ServiceInfo{
				Scripts: make(map[string]string),
			},
		}

		// 如果有指纹信息，则填充服务详情
		key := fmt.Sprintf("%s:%d", op.IP, op.Port)
		if fp, ok := fingerprintMap[key]; ok {
			portResult.Service.Name = fp.Service
			portResult.Service.Product = fp.Product
			portResult.Service.Version = fp.Version
			portResult.Service.ExtraInfo = fp.ExtraInfo
			portResult.Service.OSType = fp.OSType
			portResult.Service.DeviceType = fp.DeviceType
			portResult.Service.Hostname = fp.Hostname
			portResult.Service.CPEs = fp.CPEs
			portResult.Service.Confidence = fp.Confidence

			if fp.Banner != "" {
				portResult.Service.Scripts["banner"] = fp.Banner
			}
			if fp.Method != "" {
				portResult.Service.Scripts["detection_method"] = fp.Method
			}
		}

		scanResult.Ports = append(scanResult.Ports, portResult)
	}

	return scanResult
}
