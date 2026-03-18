package scanport

import (
	"GoSecProbe/common/log"
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ProbeParser nmap-service-probes文件解析器
type ProbeParser struct {
	Probes []*Probe
}

// Probe 探测配置
type Probe struct {
	Protocol    string   // 协议 (TCP/UDP)
	ProbeName   string   // 探测名称
	ProbeString string   // 探测字符串
	TotalWait   int      // 总等待时间(ms)
	TCPWrapped  int      // TCP包装检测时间(ms)
	Matches     []*Match // 匹配规则
	SoftMatches []*Match // 软匹配规则
	Ports       string   // 建议端口
	SSLPorts    string   // SSL端口
	Rarity      int      // 稀有度 (1-9)
}

// Match 匹配规则
type Match struct {
	Service     string            // 服务名称
	Pattern     *regexp.Regexp    // 匹配模式
	VersionInfo map[string]string // 版本信息提取规则
	IsSoft      bool              // 是否为软匹配
}

// LoadProbesFile 加载nmap-service-probes文件
func LoadProbesFile(filepath string) (*ProbeParser, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("打开指纹库文件失败: %v", err)
	}
	defer file.Close()

	parser := &ProbeParser{
		Probes: make([]*Probe, 0),
	}

	scanner := bufio.NewScanner(file)
	var currentProbe *Probe

	lineNum := 0
	skippedMatches := 0 // 统计跳过的match规则
	totalMatches := 0   // 统计总match规则
	successMatches := 0 // 统计成功的match规则

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// 跳过注释和空行
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// 解析 Probe 行
		if strings.HasPrefix(line, "Probe ") {
			// 保存前一个probe
			if currentProbe != nil {
				parser.Probes = append(parser.Probes, currentProbe)
			}

			probe, err := parseProbe(line)
			if err != nil {
				continue
			}
			currentProbe = probe
			continue
		}

		// 如果没有当前probe，跳过
		if currentProbe == nil {
			continue
		}

		// 解析match规则
		if strings.HasPrefix(line, "match ") {
			totalMatches++
			match, err := parseMatch(line, false, lineNum)
			if err != nil {
				skippedMatches++
				continue
			}
			successMatches++
			currentProbe.Matches = append(currentProbe.Matches, match)
		} else if strings.HasPrefix(line, "soft") {
			totalMatches++
			match, err := parseMatch(line, true, lineNum)
			if err != nil {
				skippedMatches++
				continue
			}
			successMatches++
			currentProbe.SoftMatches = append(currentProbe.SoftMatches, match)
		} else if strings.HasPrefix(line, "ports ") {
			currentProbe.Ports = strings.TrimPrefix(line, "ports ")
		} else if strings.HasPrefix(line, "sslports ") {
			currentProbe.SSLPorts = strings.TrimPrefix(line, "sslports ")
		} else if strings.HasPrefix(line, "totalwaitms ") {
			val := strings.TrimPrefix(line, "totalwaitms ")
			currentProbe.TotalWait, _ = strconv.Atoi(val)
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			val := strings.TrimPrefix(line, "tcpwrappedms ")
			currentProbe.TCPWrapped, _ = strconv.Atoi(val)
		} else if strings.HasPrefix(line, "rarity ") {
			val := strings.TrimPrefix(line, "rarity ")
			currentProbe.Rarity, _ = strconv.Atoi(val)
		}
	}

	// 保存最后一个probe
	if currentProbe != nil {
		parser.Probes = append(parser.Probes, currentProbe)
	}

	log.Info("[指纹库] 成功加载 %d 个探测规则, %d/%d 个匹配规则 (跳过 %d 个不兼容规则)",
		len(parser.Probes), successMatches, totalMatches, skippedMatches)
	return parser, scanner.Err()
}

// parseProbe 解析Probe行
// 格式: Probe <protocol> <probename> q|<probestring>|
func parseProbe(line string) (*Probe, error) {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil, fmt.Errorf("probe行格式错误")
	}

	probe := &Probe{
		Protocol:    parts[1],
		ProbeName:   parts[2],
		Matches:     make([]*Match, 0),
		SoftMatches: make([]*Match, 0),
	}

	// 提取probe字符串 (在q|...|之间)
	probeIdx := strings.Index(line, " q|")
	if probeIdx >= 0 {
		remaining := line[probeIdx+3:]
		endIdx := strings.Index(remaining, "|")
		if endIdx >= 0 {
			probe.ProbeString = remaining[:endIdx]
		}
	}

	return probe, nil
}

// parseMatch 解析match/softmatch行
// 格式: match <service> <pattern> [<versioninfo>]
func parseMatch(line string, isSoft bool, lineNum int) (*Match, error) {
	// 去掉 "match " 或 "softmatch " 前缀
	if isSoft {
		line = strings.TrimPrefix(line, "softmatch ")
	} else {
		line = strings.TrimPrefix(line, "match ")
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("match行格式错误")
	}

	service := parts[0]

	// 提取正则表达式模式 (在m|...|之间)
	patternIdx := strings.Index(line, " m|")
	if patternIdx < 0 {
		patternIdx = strings.Index(line, " m=")
		if patternIdx < 0 {
			patternIdx = strings.Index(line, " m%")
			if patternIdx < 0 {
				return nil, fmt.Errorf("未找到模式定义")
			}
		}
	}

	delimiter := line[patternIdx+2 : patternIdx+3]
	remaining := line[patternIdx+3:]

	// 找到模式结束位置
	endIdx := findMatchingDelimiter(remaining, delimiter)
	if endIdx < 0 {
		return nil, fmt.Errorf("未找到匹配的模式结束符")
	}

	patternStr := remaining[:endIdx]

	// 检查是否包含Go不支持的Perl语法（前瞻断言等）
	if containsUnsupportedRegex(patternStr) {
		return nil, fmt.Errorf("unsupported regex syntax")
	}

	// 预处理正则表达式，转换为Go兼容格式
	patternStr = decodePattern(patternStr)

	// 解析正则表达式
	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		return nil, err
	}

	match := &Match{
		Service:     service,
		Pattern:     pattern,
		VersionInfo: make(map[string]string),
		IsSoft:      isSoft,
	}

	// 解析版本信息 (p/.../ v/.../ i/.../ h/.../ o/.../ d/.../)
	versionPart := remaining[endIdx+1:]
	match.VersionInfo = parseVersionInfo(versionPart)

	return match, nil
}

// decodePattern 预处理正则表达式，将Perl语法转换为Go兼容格式
func decodePattern(pattern string) string {
	// 1. 将反向引用 \1, \2 等替换为通用匹配 (.*)
	// Go的regexp不支持反向引用，用通用匹配替代
	backRefRegex := regexp.MustCompile(`\\([1-9])`)
	pattern = backRefRegex.ReplaceAllString(pattern, "(.*)")

	// 2. 处理十六进制转义序列 \xHH
	hexRegex := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	pattern = hexRegex.ReplaceAllStringFunc(pattern, func(match string) string {
		hexStr := match[2:]
		val, err := strconv.ParseInt(hexStr, 16, 32)
		if err != nil {
			return match
		}
		// 对于特殊的正则字符，保持转义
		if isRegexSpecialChar(byte(val)) {
			return fmt.Sprintf("\\x%s", hexStr)
		}
		// 对于可打印字符，直接返回
		if val >= 32 && val <= 126 {
			return string(byte(val))
		}
		return match
	})

	// 3. 处理八进制转义序列 \0nn
	octalRegex := regexp.MustCompile(`\\0([0-7]{1,2})`)
	pattern = octalRegex.ReplaceAllStringFunc(pattern, func(match string) string {
		octalStr := match[2:]
		val, err := strconv.ParseInt(octalStr, 8, 32)
		if err != nil {
			return match
		}
		if val >= 32 && val <= 126 {
			return string(byte(val))
		}
		return match
	})

	return pattern
}

// isRegexSpecialChar 检查是否为正则表达式特殊字符
func isRegexSpecialChar(ch byte) bool {
	specialChars := []byte{'*', '+', '?', '{', '}', '(', ')', '[', ']', '^', '$', '|', '\\', '.'}
	for _, c := range specialChars {
		if ch == c {
			return true
		}
	}
	return false
}

// containsUnsupportedRegex 检查是否包含Go不支持的Perl正则语法
func containsUnsupportedRegex(pattern string) bool {
	// Go的regexp包不支持以下Perl语法：
	// (?=...)  - 正向前瞻断言
	// (?!...)  - 负向前瞻断言
	// (?<=...) - 正向后顾断言
	// (?<!...) - 负向后顾断言
	unsupportedPatterns := []string{
		"(?=",
		"(?!",
		"(?<=",
		"(?<!",
	}

	for _, unsupported := range unsupportedPatterns {
		if strings.Contains(pattern, unsupported) {
			return true
		}
	}
	return false
}

// findMatchingDelimiter 查找匹配的分隔符
func findMatchingDelimiter(s string, delim string) int {
	escaped := false
	for i, ch := range s {
		if escaped {
			escaped = false
			continue
		}
		if string(ch) == "\\" {
			escaped = true
			continue
		}
		if string(ch) == delim {
			return i
		}
	}
	return -1
}

// parseVersionInfo 解析版本信息
func parseVersionInfo(s string) map[string]string {
	info := make(map[string]string)

	// p/.../ = product name
	// v/.../ = version
	// i/.../ = info
	// h/.../ = hostname
	// o/.../ = operating system
	// d/.../ = device type
	// cpe:/.../ = CPE name

	for _, key := range []string{"p", "v", "i", "h", "o", "d"} {
		value := extractValue(s, key+"/")
		if value != "" {
			info[key] = value
		}
	}

	// 提取CPE
	cpe := extractValue(s, "cpe:/")
	if cpe != "" {
		info["cpe"] = "cpe:/" + cpe
	}

	return info
}

// extractValue 从字符串中提取值
func extractValue(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}

	start := idx + len(prefix)
	remaining := s[start:]

	// 查找结束的 /
	end := findMatchingDelimiter(remaining, "/")
	if end < 0 {
		return ""
	}

	return remaining[:end]
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MatchService 根据响应匹配服务
func (p *ProbeParser) MatchService(response string) *ServiceMatch {
	// 遍历所有probe的匹配规则
	for _, probe := range p.Probes {
		// 先尝试精确匹配
		for _, match := range probe.Matches {
			if match.Pattern.MatchString(response) {
				return &ServiceMatch{
					Service:    match.Service,
					Match:      match,
					Probe:      probe,
					Confidence: 100,
				}
			}
		}

		// 再尝试软匹配
		for _, match := range probe.SoftMatches {
			if match.Pattern.MatchString(response) {
				return &ServiceMatch{
					Service:    match.Service,
					Match:      match,
					Probe:      probe,
					Confidence: 70,
				}
			}
		}
	}

	return nil
}

// ServiceMatch 服务匹配结果
type ServiceMatch struct {
	Service    string
	Match      *Match
	Probe      *Probe
	Confidence int
}

// ExtractVersionInfo 从响应中提取版本信息
func (sm *ServiceMatch) ExtractVersionInfo(response string) map[string]string {
	result := make(map[string]string)

	// 获取正则匹配的捕获组
	matches := sm.Match.Pattern.FindStringSubmatch(response)
	if len(matches) <= 1 {
		// 没有捕获组，返回基本信息
		for k, v := range sm.Match.VersionInfo {
			result[k] = v
		}
		return result
	}

	// 处理版本信息模板，替换 $1, $2 等
	for k, template := range sm.Match.VersionInfo {
		value := template
		for i := 1; i < len(matches); i++ {
			placeholder := fmt.Sprintf("$%d", i)
			value = strings.ReplaceAll(value, placeholder, matches[i])
		}
		result[k] = value
	}

	return result
}

// GetNULLProbe 获取 NULL 探测（用于获取主动发送的 Banner）
func (p *ProbeParser) GetNULLProbe() *Probe {
	for _, probe := range p.Probes {
		if probe.ProbeName == "NULL" {
			return probe
		}
	}
	return nil
}

// GetProbesForPort 获取适用于指定端口的探测规则（按稀有度排序）
func (p *ProbeParser) GetProbesForPort(port uint16) []*Probe {
	result := make([]*Probe, 0)
	portStr := fmt.Sprintf("%d", port)

	// 收集所有适用的探测规则
	for _, probe := range p.Probes {
		// 跳过 NULL 探测（应该单独处理）
		if probe.ProbeName == "NULL" {
			continue
		}

		// 检查是否在推荐端口列表中
		if probe.Ports != "" && strings.Contains(probe.Ports, portStr) {
			result = append(result, probe)
			continue
		}

		// 如果没有明确的端口限制，也包含进来（但优先级较低）
		if probe.Ports == "" {
			result = append(result, probe)
		}
	}

	// 按稀有度排序（稀有度低的优先，即常见服务优先）
	// Nmap 的稀有度：1=最常见，9=最罕见
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Rarity > result[j].Rarity {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}
