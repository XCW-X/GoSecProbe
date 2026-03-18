package common

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Target 扫描目标结构
type Target struct {
	Original string   // 原始输入
	Host     string   // 主机名或IP
	IP       string   // 解析后的IP地址
	Port     int      // 端口号（如果有）
	IsCIDR   bool     // 是否为CIDR格式
	IPs      []string // CIDR解析后的IP列表
}

// TargetParser 目标解析器
type TargetParser struct {
	EnableDNS bool     // 是否启用DNS解析
	Blacklist []string // 黑名单主机/IP列表
}

// NewTargetParser 创建目标解析器
func NewTargetParser(enableDNS bool) *TargetParser {
	return &TargetParser{
		EnableDNS: enableDNS,
		Blacklist: make([]string, 0),
	}
}

// SetBlacklist 设置黑名单
func (p *TargetParser) SetBlacklist(hosts string) {
	if hosts == "" {
		return
	}
	lines := splitByDelimiters(hosts)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			p.Blacklist = append(p.Blacklist, line)
		}
	}
}

// isBlacklisted 检查主机是否在黑名单中
func (p *TargetParser) isBlacklisted(host string) bool {
	for _, b := range p.Blacklist {
		if host == b {
			return true
		}
	}
	return false
}

// ParseTargets 解析多个目标（支持多行、逗号分隔）
func (p *TargetParser) ParseTargets(input string) ([]*Target, error) {
	if input == "" {
		return nil, fmt.Errorf("目标不能为空")
	}

	// 分割输入（支持换行、逗号、分号、空格）
	lines := splitByDelimiters(input)

	targets := make([]*Target, 0)
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析单个目标
		target, err := p.ParseTarget(line)
		if err != nil {
			// 记录错误但继续处理其他目标
			continue
		}

		// 如果是CIDR，展开所有IP
		if target.IsCIDR {
			for _, ip := range target.IPs {
				if !seen[ip] && !p.isBlacklisted(ip) {
					seen[ip] = true
					targets = append(targets, &Target{
						Original: line,
						Host:     ip,
						IP:       ip,
						IsCIDR:   false,
					})
				}
			}
		} else {
			// 去重并在黑名单中过滤
			key := target.IP
			if key == "" {
				key = target.Host
			}
			if !seen[key] && !p.isBlacklisted(target.Host) && !p.isBlacklisted(target.IP) {
				seen[key] = true
				targets = append(targets, target)
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("未找到有效的扫描目标")
	}

	return targets, nil
}

// ParseTarget 解析单个目标
func (p *TargetParser) ParseTarget(input string) (*Target, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("目标为空")
	}

	target := &Target{
		Original: input,
	}

	// 1. 检查是否为CIDR格式
	if p.isCIDR(input) {
		return p.parseCIDR(input)
	}

	// 2. 检查是否为URL格式
	if p.isURL(input) {
		return p.parseURL(input)
	}

	// 3. 检查是否为IP:Port格式
	if strings.Contains(input, ":") && !strings.Contains(input, "://") {
		return p.parseIPPort(input)
	}

	// 4. 检查是否为纯IP地址
	if p.isIP(input) {
		target.Host = input
		target.IP = input
		return target, nil
	}

	// 5. 作为域名处理
	return p.parseDomain(input)
}

// isCIDR 检查是否为CIDR格式
func (p *TargetParser) isCIDR(input string) bool {
	_, _, err := net.ParseCIDR(input)
	return err == nil
}

// parseCIDR 解析CIDR
func (p *TargetParser) parseCIDR(input string) (*Target, error) {
	_, ipNet, err := net.ParseCIDR(input)
	if err != nil {
		return nil, fmt.Errorf("无效的CIDR格式: %v", err)
	}

	// 生成IP列表
	ips := generateIPsFromCIDR(ipNet)

	return &Target{
		Original: input,
		Host:     input,
		IsCIDR:   true,
		IPs:      ips,
	}, nil
}

// isURL 检查是否为URL格式
func (p *TargetParser) isURL(input string) bool {
	return strings.HasPrefix(input, "http://") ||
		strings.HasPrefix(input, "https://") ||
		strings.HasPrefix(input, "ftp://")
}

// parseURL 解析URL
func (p *TargetParser) parseURL(input string) (*Target, error) {
	// 如果没有协议，添加默认协议
	if !strings.Contains(input, "://") {
		input = "http://" + input
	}

	u, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("无效的URL格式: %v", err)
	}

	target := &Target{
		Original: input,
		Host:     u.Hostname(),
	}

	// 提取端口
	if u.Port() != "" {
		var port int
		fmt.Sscanf(u.Port(), "%d", &port)
		target.Port = port
	}

	// DNS解析
	if p.EnableDNS && !p.isIP(target.Host) {
		ip, err := p.resolveHost(target.Host)
		if err == nil {
			target.IP = ip
		}
	} else if p.isIP(target.Host) {
		target.IP = target.Host
	}

	return target, nil
}

// parseIPPort 解析IP:Port格式
func (p *TargetParser) parseIPPort(input string) (*Target, error) {
	host, portStr, err := net.SplitHostPort(input)
	if err != nil {
		return nil, fmt.Errorf("无效的IP:Port格式: %v", err)
	}

	target := &Target{
		Original: input,
		Host:     host,
	}

	// 解析端口
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	target.Port = port

	// 检查是否为IP
	if p.isIP(host) {
		target.IP = host
	} else if p.EnableDNS {
		// DNS解析
		ip, err := p.resolveHost(host)
		if err == nil {
			target.IP = ip
		}
	}

	return target, nil
}

// parseDomain 解析域名
func (p *TargetParser) parseDomain(input string) (*Target, error) {
	// 验证域名格式
	if !p.isValidDomain(input) {
		return nil, fmt.Errorf("无效的域名格式: %s", input)
	}

	target := &Target{
		Original: input,
		Host:     input,
	}

	// DNS解析
	if p.EnableDNS {
		ip, err := p.resolveHost(input)
		if err == nil {
			target.IP = ip
		}
	}

	return target, nil
}

// isIP 检查是否为IP地址
func (p *TargetParser) isIP(input string) bool {
	return net.ParseIP(input) != nil
}

// isValidDomain 验证域名格式
func (p *TargetParser) isValidDomain(domain string) bool {
	// 简单的域名格式验证
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// resolveHost DNS解析主机名
func (p *TargetParser) resolveHost(host string) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}

	// 优先返回IPv4地址
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// 如果没有IPv4，返回IPv6
	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("无法解析主机: %s", host)
}

// splitByDelimiters 按多种分隔符分割字符串
func splitByDelimiters(input string) []string {
	// 替换所有分隔符为换行符
	input = strings.ReplaceAll(input, ",", "\n")
	input = strings.ReplaceAll(input, ";", "\n")
	input = strings.ReplaceAll(input, " ", "\n")
	input = strings.ReplaceAll(input, "\t", "\n")

	// 按换行符分割
	lines := strings.Split(input, "\n")

	// 过滤空行
	result := make([]string, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}

	return result
}

// ExtractIPs 从目标列表中提取所有IP地址
func ExtractIPs(targets []*Target) []string {
	ips := make([]string, 0)
	for _, target := range targets {
		if target.IP != "" {
			ips = append(ips, target.IP)
		} else if target.Host != "" && net.ParseIP(target.Host) != nil {
			ips = append(ips, target.Host)
		}
	}
	return ips
}

// ExtractHosts 从目标列表中提取所有主机名
func ExtractHosts(targets []*Target) []string {
	hosts := make([]string, 0)
	for _, target := range targets {
		if target.Host != "" {
			hosts = append(hosts, target.Host)
		}
	}
	return hosts
}

// generateIPsFromCIDR 从CIDR生成所有IP地址
func generateIPsFromCIDR(ipNet *net.IPNet) []string {
	var ips []string

	// 获取起始IP
	ip := ipNet.IP.Mask(ipNet.Mask)

	// 遍历所有IP
	for ipNet.Contains(ip) {
		// 跳过网络地址和广播地址
		if !isNetworkOrBroadcast(ip, ipNet) {
			ips = append(ips, ip.String())
		}

		// 递增IP
		ip = nextIP(ip)
	}

	return ips
}

// nextIP 获取下一个IP地址
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	return next
}

// isNetworkOrBroadcast 检查是否为网络地址或广播地址
func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	// 网络地址
	if ip.Equal(ipNet.IP) {
		return true
	}

	// 广播地址
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}
	if ip.Equal(broadcast) {
		return true
	}

	return false
}

// FilterPorts 从端口列表中移除黑名单中的端口
func FilterPorts(ports string, blacklist string) string {
	if blacklist == "" {
		return ports
	}

	blines := splitByDelimiters(blacklist)
	blacklisted := make(map[string]bool)
	for _, b := range blines {
		blacklisted[b] = true
	}

	ptLines := strings.Split(ports, ",")
	var result []string
	for _, p := range ptLines {
		if !blacklisted[strings.TrimSpace(p)] {
			result = append(result, p)
		}
	}
	return strings.Join(result, ",")
}
