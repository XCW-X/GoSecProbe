package scanport

import (
	"GoSecProbe/common/log"
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
)

// PortScanner 端口扫描器
type PortScanner struct {
	Timeout        time.Duration // 超时时间
	EnableService  bool          // 是否启用服务识别
	EnableVersions bool          // 是否启用版本检测
	EnableScripts  bool          // 是否启用NSE脚本
	Concurrency    int           // 并发数
	MaxRetries     int           // 最大重试次数
	TimingTemplate int           // 时间模板 (0-5)
}

// NewPortScanner 创建端口扫描器实例
func NewPortScanner(timeout time.Duration, concurrency int) *PortScanner {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	if concurrency == 0 {
		concurrency = 100
	}
	return &PortScanner{
		Timeout:        timeout,
		EnableService:  true,
		EnableVersions: true,
		EnableScripts:  false,
		Concurrency:    concurrency,
		MaxRetries:     2,
		TimingTemplate: 4, // 默认使用 T4 (aggressive)
	}
}

// PortResult 端口扫描结果
type PortResult struct {
	IP       string      // IP地址
	Port     uint16      // 端口号
	Protocol string      // 协议类型 (tcp/udp)
	State    string      // 端口状态 (open/closed/filtered)
	Service  ServiceInfo // 服务信息
	Error    error       // 错误信息
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name       string            // 服务名称
	Product    string            // 产品名称
	Version    string            // 版本信息
	ExtraInfo  string            // 额外信息
	OSType     string            // 操作系统类型
	Hostname   string            // 主机名
	DeviceType string            // 设备类型
	Confidence int               // 置信度 (0-10)
	CPEs       []string          // CPE列表
	Scripts    map[string]string // 脚本扫描结果
}

// ScanResult 完整的扫描结果
type ScanResult struct {
	IP            string        // IP地址
	Hostname      []string      // 主机名
	Ports         []PortResult  // 开放端口列表
	OS            OSInfo        // 操作系统信息
	TotalPorts    int           // 总端口数
	OpenPorts     int           // 开放端口数
	ClosedPorts   int           // 关闭端口数
	FilteredPorts int           // 过滤端口数
	ScanDuration  time.Duration // 扫描耗时
	Error         error         // 错误信息
}

// OSInfo 操作系统信息
type OSInfo struct {
	Name     string   // 操作系统名称
	Accuracy int      // 准确度
	OSFamily string   // 系统家族
	OSGen    string   // 系统代次
	Vendor   string   // 厂商
	CPEs     []string // CPE列表
}

// ScanPorts 扫描单个主机的端口
func (s *PortScanner) ScanPorts(ctx context.Context, ip string, portRange string) (*ScanResult, error) {
	startTime := time.Now()

	log.Info("[端口扫描] 开始扫描 %s 端口范围: %s", ip, portRange)

	// 创建 nmap 扫描器
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(ip),
		nmap.WithPorts(portRange),
		nmap.WithServiceInfo(),
	)

	if err != nil {
		return nil, fmt.Errorf("创建nmap扫描器失败: %v", err)
	}

	// 设置扫描选项
	if s.EnableVersions {
		scanner.AddOptions(nmap.WithVersionAll())
	}

	// 设置时间模板
	switch s.TimingTemplate {
	case 0:
		scanner.AddOptions(nmap.WithTimingTemplate(nmap.TimingSlowest))
	case 1:
		scanner.AddOptions(nmap.WithTimingTemplate(nmap.TimingSneaky))
	case 2:
		scanner.AddOptions(nmap.WithTimingTemplate(nmap.TimingPolite))
	case 3:
		scanner.AddOptions(nmap.WithTimingTemplate(nmap.TimingNormal))
	case 4:
		scanner.AddOptions(nmap.WithTimingTemplate(nmap.TimingAggressive))
	case 5:
		scanner.AddOptions(nmap.WithTimingTemplate(nmap.TimingFastest))
	}

	// 启用脚本扫描
	if s.EnableScripts {
		scanner.AddOptions(nmap.WithScripts("default"))
	}

	// 设置最大重试次数
	if s.MaxRetries > 0 {
		scanner.AddOptions(nmap.WithMaxRetries(s.MaxRetries))
	}

	// 执行扫描
	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("nmap扫描失败: %v", err)
	}

	// 输出警告信息
	if len(*warnings) > 0 {
		for _, warning := range *warnings {
			log.Info("[端口扫描-警告] %s", warning)
		}
	}

	// 检查是否有扫描结果
	if len(result.Hosts) == 0 {
		return &ScanResult{
			IP:           ip,
			Ports:        []PortResult{},
			ScanDuration: time.Since(startTime),
			Error:        fmt.Errorf("未发现主机"),
		}, nil
	}

	// 解析扫描结果
	scanResult := s.parseNmapResult(result.Hosts[0], time.Since(startTime))
	scanResult.IP = ip

	log.Info("[端口扫描] 完成 %s: 发现 %d 个开放端口 (耗时: %v)",
		ip, scanResult.OpenPorts, scanResult.ScanDuration)

	return scanResult, nil
}

// ScanMultipleHosts 批量扫描多个主机的端口
func (s *PortScanner) ScanMultipleHosts(ctx context.Context, ips []string, portRange string) []ScanResult {
	results := make([]ScanResult, len(ips))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Concurrency)

	for i, ip := range ips {
		wg.Add(1)
		go func(index int, target string) {
			defer wg.Done()

			// 控制并发
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				results[index] = ScanResult{
					IP:    target,
					Ports: []PortResult{},
					Error: ctx.Err(),
				}
				return
			default:
			}

			// 执行扫描
			result, err := s.ScanPorts(ctx, target, portRange)
			if err != nil {
				results[index] = ScanResult{
					IP:    target,
					Ports: []PortResult{},
					Error: err,
				}
				return
			}

			results[index] = *result
		}(i, ip)
	}

	wg.Wait()
	return results
}

// parseNmapResult 解析nmap扫描结果
func (s *PortScanner) parseNmapResult(host nmap.Host, duration time.Duration) *ScanResult {
	result := &ScanResult{
		Hostname:     []string{},
		Ports:        []PortResult{},
		ScanDuration: duration,
	}

	// 解析主机名
	for _, hostname := range host.Hostnames {
		result.Hostname = append(result.Hostname, hostname.Name)
	}

	// 解析操作系统信息
	if len(host.OS.Matches) > 0 {
		bestMatch := host.OS.Matches[0]
		result.OS = OSInfo{
			Name:     bestMatch.Name,
			Accuracy: bestMatch.Accuracy,
		}

		if len(bestMatch.Classes) > 0 {
			class := bestMatch.Classes[0]
			result.OS.OSFamily = class.Family
			result.OS.OSGen = class.OSGeneration
			result.OS.Vendor = class.Vendor

			for _, cpe := range class.CPEs {
				result.OS.CPEs = append(result.OS.CPEs, string(cpe))
			}
		}
	}

	// 统计端口状态
	result.TotalPorts = len(host.Ports)
	for _, port := range host.Ports {
		switch port.State.State {
		case "open":
			result.OpenPorts++
		case "closed":
			result.ClosedPorts++
		case "filtered":
			result.FilteredPorts++
		}
	}

	// 只解析开放的端口
	for _, port := range host.Ports {
		if port.State.State != "open" {
			continue
		}

		portResult := PortResult{
			Port:     port.ID,
			Protocol: port.Protocol,
			State:    port.State.State,
			Service: ServiceInfo{
				Name:       port.Service.Name,
				Product:    port.Service.Product,
				Version:    port.Service.Version,
				ExtraInfo:  port.Service.ExtraInfo,
				OSType:     port.Service.OSType,
				Hostname:   port.Service.Hostname,
				DeviceType: port.Service.DeviceType,
				Confidence: port.Service.Confidence,
				Scripts:    make(map[string]string),
			},
		}

		// 解析CPE
		for _, cpe := range port.Service.CPEs {
			portResult.Service.CPEs = append(portResult.Service.CPEs, string(cpe))
		}

		// 解析脚本输出
		for _, script := range port.Scripts {
			portResult.Service.Scripts[script.ID] = script.Output
		}

		result.Ports = append(result.Ports, portResult)
	}

	return result
}

// ParsePortRange 解析端口范围字符串
func ParsePortRange(portRange string) (string, error) {
	// 预定义的端口范围
	switch strings.ToLower(portRange) {
	case "top1000":
		return getTopPortsOrFallback(1000), nil
	case "udptop100":
		return GetUDPTop100Ports(), nil
	case "all":
		return "1-65535", nil
	case "":
		return getTopPortsOrFallback(1000), nil
	default:
		// 验证自定义端口范围格式
		if err := validatePortRange(portRange); err != nil {
			return "", err
		}
		return portRange, nil
	}
}

// GetUDPTop100Ports 返回 UDP TOP100 常用端口列表
// 来源：nmap 统计的最常见 UDP 服务端口
func GetUDPTop100Ports() string {
	return "53,67,68,69,111,123,135,137,138,139,161,162,177,445," +
		"500,514,520,623,626,631,1434,1514,1604,1701,1718,1719,1900,2049," +
		"2222,2302,2483,3283,3478,3671,4500,4672,5353,5683,6481,6502," +
		"7777,8900,9200,10000,17185,20031,23945,26000,27015,30718,31337," +
		"32768,32769,32815,33281,49152,49153,49154,49156,49181,49182," +
		"49185,49186,49188,49190,49191,49192,49193,49194,49200,49201," +
		"63963"
}

var topPortsOnce sync.Once
var topPortsCache string

func getTopPortsOrFallback(limit int) string {
	ports, err := GetTopPorts(limit)
	if err != nil || ports == "" {
		return "1-1000"
	}
	return ports
}

func GetTopPorts(limit int) (string, error) {
	topPortsOnce.Do(func() {
		topPortsCache, _ = loadTopPorts(limit)
	})
	if topPortsCache == "" {
		return "", fmt.Errorf("top ports unavailable")
	}
	return topPortsCache, nil
}

func loadTopPorts(limit int) (string, error) {
	file, err := os.Open("./service/lib/nmap-services.txt")
	if err != nil {
		return "", err
	}
	defer file.Close()

	type portFreq struct {
		port int
		freq float64
	}
	portFreqMap := make(map[int]float64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		portProto := fields[1]
		freqStr := fields[2]
		parts := strings.Split(portProto, "/")
		if len(parts) != 2 {
			continue
		}
		if parts[1] != "tcp" {
			continue
		}
		port, err := strconv.Atoi(parts[0])
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		freq, err := strconv.ParseFloat(freqStr, 64)
		if err != nil {
			continue
		}
		if existing, ok := portFreqMap[port]; !ok || freq > existing {
			portFreqMap[port] = freq
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	ports := make([]portFreq, 0, len(portFreqMap))
	for port, freq := range portFreqMap {
		ports = append(ports, portFreq{port: port, freq: freq})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].freq == ports[j].freq {
			return ports[i].port < ports[j].port
		}
		return ports[i].freq > ports[j].freq
	})

	if limit > len(ports) {
		limit = len(ports)
	}
	portList := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		portList = append(portList, strconv.Itoa(ports[i].port))
	}
	return strings.Join(portList, ","), nil
}

// validatePortRange 验证端口范围格式
func validatePortRange(portRange string) error {
	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// 范围格式 如 "1-100"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return fmt.Errorf("无效的端口范围格式: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil || start < 1 || start > 65535 {
				return fmt.Errorf("无效的起始端口: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil || end < 1 || end > 65535 {
				return fmt.Errorf("无效的结束端口: %s", rangeParts[1])
			}
			if start > end {
				return fmt.Errorf("起始端口不能大于结束端口: %s", part)
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("无效的端口号: %s", part)
			}
		}
	}
	return nil
}

// ScanUDPPorts 扫描单个主机的 UDP 端口（使用 nmap -sU，需要 root 权限）
func (s *PortScanner) ScanUDPPorts(ctx context.Context, ip string, udpPortRange string) (*ScanResult, error) {
	startTime := time.Now()

	// 解析 UDP 端口范围
	portStr := udpPortRange
	if strings.ToLower(udpPortRange) == "udptop100" {
		portStr = GetUDPTop100Ports()
	}

	log.Info("[UDP扫描] 开始扫描 %s UDP端口: %s", ip, portStr)

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(ip),
		nmap.WithPorts(portStr),
		nmap.WithUDPScan(), // -sU
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithMaxRetries(1),
	)
	if err != nil {
		return nil, fmt.Errorf("创建UDP nmap扫描器失败: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("UDP nmap扫描失败: %v", err)
	}

	if len(*warnings) > 0 {
		for _, w := range *warnings {
			log.Info("[UDP扫描-警告] %s", w)
		}
	}

	if len(result.Hosts) == 0 {
		return &ScanResult{IP: ip, Ports: []PortResult{}, ScanDuration: time.Since(startTime)}, nil
	}

	scanResult := s.parseNmapResult(result.Hosts[0], time.Since(startTime))
	scanResult.IP = ip
	log.Info("[UDP扫描] 完成 %s: 发现 %d 个UDP开放端口 (耗时: %v)",
		ip, scanResult.OpenPorts, scanResult.ScanDuration)
	return scanResult, nil
}

// GetOpenPorts 从扫描结果中获取所有开放的端口
func GetOpenPorts(results []ScanResult) []PortResult {
	ports := make([]PortResult, 0)
	for _, result := range results {
		ports = append(ports, result.Ports...)
	}
	return ports
}

// GetHostsWithOpenPorts 获取有开放端口的主机列表
func GetHostsWithOpenPorts(results []ScanResult) []string {
	hosts := make([]string, 0)
	for _, result := range results {
		if result.OpenPorts > 0 {
			hosts = append(hosts, result.IP)
		}
	}
	return hosts
}
