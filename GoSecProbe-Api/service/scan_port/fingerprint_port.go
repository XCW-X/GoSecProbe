package scanport

import (
	"GoSecProbe/common/log"
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// FingerprintScanner 指纹识别扫描器
type FingerprintScanner struct {
	Timeout      time.Duration
	ProbesParser *ProbeParser
}

// NewFingerprintScanner 创建指纹扫描器实例
func NewFingerprintScanner(timeout time.Duration, probesFile string) (*FingerprintScanner, error) {
	scanner := &FingerprintScanner{
		Timeout: timeout,
	}

	// 加载指纹库
	if probesFile != "" {
		parser, err := LoadProbesFile(probesFile)
		if err != nil {
			return nil, fmt.Errorf("加载指纹库失败: %v", err)
		}
		scanner.ProbesParser = parser
		log.Info("[指纹识别] 成功加载指纹库: %d 个探测规则", len(parser.Probes))
	}

	return scanner, nil
}

// Fingerprint 指纹信息
type Fingerprint struct {
	IP          string
	Port        uint16
	Protocol    string
	Service     string
	Product     string
	Version     string
	ExtraInfo   string
	Hostname    string
	OSType      string
	DeviceType  string
	CPEs        []string
	Banner      string
	Confidence  int
	Method      string
	RawResponse string
}

// FingerprintPort 对单个端口进行指纹识别（完整 Nmap 流程）
func (f *FingerprintScanner) FingerprintPort(ctx context.Context, ip string, port uint16, protocol string) (*Fingerprint, error) {
	fingerprint := &Fingerprint{
		IP:       ip,
		Port:     port,
		Protocol: protocol,
	}

	// 仅支持TCP协议
	if protocol != "tcp" {
		fingerprint.Service = "unknown"
		fingerprint.Method = "不支持的协议"
		return fingerprint, nil
	}

	// 如果没有指纹库，无法进行识别
	if f.ProbesParser == nil {
		fingerprint.Service = "unknown"
		fingerprint.Method = "指纹库未加载"
		return fingerprint, fmt.Errorf("指纹库未加载")
	}

	// 步骤1：尝试 NULL 探测（获取主动发送的 Banner）
	response, err := f.sendNULLProbe(ctx, ip, port)
	if err == nil && response != "" {
		// 尝试匹配响应
		if f.matchAndFill(fingerprint, response, "NULL探测") {
			return fingerprint, nil
		}
	}

	// 步骤2：获取适用于该端口的所有 Nmap 探测规则
	probes := f.ProbesParser.GetProbesForPort(port)
	if len(probes) == 0 {
		fingerprint.Service = "unknown"
		fingerprint.Confidence = 0
		fingerprint.Method = "无适用探测规则"
		return fingerprint, nil
	}

	// 步骤3：依次发送探测包并尝试匹配
	maxProbes := 5 // 限制最多尝试的探测数，避免耗时过长
	for i, probe := range probes {
		if i >= maxProbes {
			break
		}

		// 发送探测包
		probeResponse, err := f.sendProbe(ctx, ip, port, probe)
		if err != nil {
			continue // 这个探测失败，尝试下一个
		}

		// 尝试匹配响应
		if probeResponse != "" {
			methodName := fmt.Sprintf("Nmap-%s探测", probe.ProbeName)
			if f.matchAndFill(fingerprint, probeResponse, methodName) {
				return fingerprint, nil
			}
		}
	}

	// 所有探测都失败，标记为 unknown
	fingerprint.Service = "unknown"
	fingerprint.Confidence = 0
	fingerprint.Method = "所有探测均未匹配"
	return fingerprint, nil
}

// sendNULLProbe 发送 NULL 探测（不发送数据，只接收主动 Banner）
func (f *FingerprintScanner) sendNULLProbe(ctx context.Context, ip string, port uint16) (string, error) {
	address := fmt.Sprintf("%s:%d", ip, port)

	// 创建连接
	dialer := &net.Dialer{
		Timeout: f.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(f.Timeout))

	// 读取主动发送的 Banner（不发送任何数据）
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return "", err
	}

	return string(buffer[:n]), nil
}

// sendProbe 发送指定的 Nmap 探测包并接收响应
func (f *FingerprintScanner) sendProbe(ctx context.Context, ip string, port uint16, probe *Probe) (string, error) {
	address := fmt.Sprintf("%s:%d", ip, port)

	// 创建连接
	dialer := &net.Dialer{
		Timeout: f.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 发送探测包
	probeData := []byte(probe.ProbeString)
	_, err = conn.Write(probeData)
	if err != nil {
		return "", err
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(f.Timeout))

	// 读取响应
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return "", err
	}

	return string(buffer[:n]), nil
}

// matchAndFill 尝试匹配响应并填充指纹信息
func (f *FingerprintScanner) matchAndFill(fp *Fingerprint, response string, method string) bool {
	if response == "" {
		return false
	}

	// 保存原始响应
	fp.Banner = response
	fp.RawResponse = response

	// 使用指纹库匹配
	match := f.ProbesParser.MatchService(response)
	if match == nil {
		return false
	}

	// 填充服务信息
	fp.Service = match.Service
	fp.Confidence = match.Confidence
	fp.Method = method

	// 提取版本信息
	versionInfo := match.ExtractVersionInfo(response)
	if product, ok := versionInfo["p"]; ok {
		fp.Product = product
	}
	if version, ok := versionInfo["v"]; ok {
		fp.Version = version
	}
	if info, ok := versionInfo["i"]; ok {
		fp.ExtraInfo = info
	}
	if hostname, ok := versionInfo["h"]; ok {
		fp.Hostname = hostname
	}
	if ostype, ok := versionInfo["o"]; ok {
		fp.OSType = ostype
	}
	if devicetype, ok := versionInfo["d"]; ok {
		fp.DeviceType = devicetype
	}
	if cpe, ok := versionInfo["cpe"]; ok {
		fp.CPEs = append(fp.CPEs, cpe)
	}

	return true
}

// ScanBanner 快速banner抓取（不进行深度识别）
func ScanBanner(ip string, port uint16, timeout time.Duration) (string, error) {
	address := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	scanner := bufio.NewScanner(conn)
	var lines []string
	for scanner.Scan() && len(lines) < 10 {
		lines = append(lines, scanner.Text())
	}

	return strings.Join(lines, "\n"), nil
}

// EnhancePortResultWithFingerprint 使用指纹信息增强端口扫描结果
func EnhancePortResultWithFingerprint(portResult *PortResult, fingerprint *Fingerprint) {
	if fingerprint == nil {
		return
	}

	// 如果指纹识别的置信度高于原有信息，则更新
	if fingerprint.Confidence > portResult.Service.Confidence {
		if fingerprint.Service != "" && fingerprint.Service != "unknown" {
			portResult.Service.Name = fingerprint.Service
		}
		if fingerprint.Product != "" {
			portResult.Service.Product = fingerprint.Product
		}
		if fingerprint.Version != "" {
			portResult.Service.Version = fingerprint.Version
		}
		if fingerprint.ExtraInfo != "" {
			portResult.Service.ExtraInfo = fingerprint.ExtraInfo
		}
		if fingerprint.OSType != "" {
			portResult.Service.OSType = fingerprint.OSType
		}
		if fingerprint.DeviceType != "" {
			portResult.Service.DeviceType = fingerprint.DeviceType
		}
		if fingerprint.Hostname != "" {
			portResult.Service.Hostname = fingerprint.Hostname
		}
		if len(fingerprint.CPEs) > 0 {
			portResult.Service.CPEs = fingerprint.CPEs
		}

		portResult.Service.Confidence = fingerprint.Confidence
	}

	// 添加banner到脚本输出中
	if fingerprint.Banner != "" {
		if portResult.Service.Scripts == nil {
			portResult.Service.Scripts = make(map[string]string)
		}
		portResult.Service.Scripts["banner"] = fingerprint.Banner
	}
}

// BatchFingerprint 批量进行指纹识别
func (f *FingerprintScanner) BatchFingerprint(ctx context.Context, portResults []PortResult) []*Fingerprint {
	fingerprints := make([]*Fingerprint, len(portResults))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // 限制并发数

	for i, pr := range portResults {
		wg.Add(1)
		go func(index int, portRes PortResult) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fp, err := f.FingerprintPort(ctx, portRes.IP, portRes.Port, portRes.Protocol)
			if err != nil {
				log.Info("[指纹识别] %s:%d 识别失败: %v", portRes.IP, portRes.Port, err)
				fp = &Fingerprint{
					IP:       portRes.IP,
					Port:     portRes.Port,
					Protocol: portRes.Protocol,
					Service:  "unknown",
					Method:   "error",
				}
			}
			fingerprints[index] = fp
		}(i, pr)
	}

	wg.Wait()
	return fingerprints
}
