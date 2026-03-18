package model

import "time"

// VulnSeverity 漏洞严重程度
type VulnSeverity string

const (
	SeverityInfo     VulnSeverity = "info"
	SeverityLow      VulnSeverity = "low"
	SeverityMedium   VulnSeverity = "medium"
	SeverityHigh     VulnSeverity = "high"
	SeverityCritical VulnSeverity = "critical"
)

// Asset 资产信息
type Asset struct {
	IP       string   `json:"ip"`       // IP地址
	Hostname string   `json:"hostname"` // 主机名
	Ports    []int    `json:"ports"`    // 开放端口列表
	Services []string `json:"services"` // 服务列表
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Port        int                    `json:"port"`        // 端口
	Protocol    string                 `json:"protocol"`    // 协议 (TCP/UDP)
	Service     string                 `json:"service"`     // 服务名称 (HTTP/SSH/MySQL等)
	Version     string                 `json:"version"`     // 版本信息
	Banner      string                 `json:"banner"`      // Banner信息
	Fingerprint map[string]interface{} `json:"fingerprint"` // 指纹信息
	IsTLS       bool                   `json:"is_tls"`      // 是否TLS加密
}

// Fingerprint Web指纹信息
type Fingerprint struct {
	// 核心字段 - wappalyzer 原始识别结果（指纹驱动的核心）
	Technologies []string `json:"technologies"` // 所有识别到的技术栈（直接来自 wappalyzer）

	// 服务器信息
	Server        string `json:"server"`         // 服务器 (Nginx/Apache等)
	ServerVersion string `json:"server_version"` // 服务器版本

	// 分类信息（可选，用于快速查询，但不作为指纹驱动的依据）
	Framework  string   `json:"framework"`  // 框架 (Spring/Django/Laravel等)
	CMS        string   `json:"cms"`        // CMS (WordPress/Joomla等)
	Languages  []string `json:"languages"`  // 编程语言
	Components []string `json:"components"` // 组件 (jQuery/Vue等)

	// 安全信息
	WAF string `json:"waf"` // WAF信息
	CDN string `json:"cdn"` // CDN信息

	// 来源信息
	Port int    `json:"port"` // 对应的端口
	URL  string `json:"url"`  // 探测的URL
}

// VulnEvidence 漏洞证据
type VulnEvidence struct {
	Request       string            `json:"request"`        // 请求内容
	Response      string            `json:"response"`       // 响应内容
	MatchedAt     string            `json:"matched_at"`     // 匹配位置
	ExtractedData map[string]string `json:"extracted_data"` // 提取的数据
	CurlCommand   string            `json:"curl_command"`   // cURL命令（便于复现）
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID      int    `json:"id"`      // 漏洞ID
	TaskID  int    `json:"task_id"` // 关联的任务ID
	Target  string `json:"target"`  // 目标（URL或IP）
	IP      string `json:"ip"`      // IP地址
	Port    int    `json:"port"`    // 端口
	Service string `json:"service"` // 服务类型

	// 漏洞基本信息
	Name        string       `json:"name"`        // 漏洞名称
	Description string       `json:"description"` // 漏洞描述
	Severity    VulnSeverity `json:"severity"`    // 严重程度
	Type        string       `json:"type"`        // 漏洞类型

	// CVE/CWE信息
	CVE  string  `json:"cve"`  // CVE编号
	CWE  string  `json:"cwe"`  // CWE编号
	CVSS float64 `json:"cvss"` // CVSS分数

	// Nuclei模板信息
	TemplateID   string   `json:"template_id"`   // 模板ID
	TemplatePath string   `json:"template_path"` // 模板路径
	Author       string   `json:"author"`        // 模板作者
	Tags         []string `json:"tags"`          // 标签
	Reference    []string `json:"reference"`     // 参考链接

	// 证据信息
	Evidence VulnEvidence `json:"evidence"` // 漏洞证据

	// 其他信息
	Metadata  string    `json:"metadata"`   // 元数据（JSON格式）
	Status    string    `json:"status"`     // 状态：new/confirmed/false_positive/fixed
	CreatedAt time.Time `json:"created_at"` // 发现时间
	UpdatedAt time.Time `json:"updated_at"` // 更新时间
}

// ScanResult 扫描结果
type ScanResult struct {
	TaskID          int             `json:"task_id"`
	Target          string          `json:"target"`
	Asset           Asset           `json:"asset"`
	Services        []ServiceInfo   `json:"services"`
	Fingerprints    []Fingerprint   `json:"fingerprints"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        int             `json:"duration"` // 扫描耗时（秒）
}

// TemplateFilter 模板过滤器
type TemplateFilter struct {
	Services   []string `json:"services"`   // 需要的服务类型
	Frameworks []string `json:"frameworks"` // 需要的框架
	CMS        []string `json:"cms"`        // 需要的CMS
	Tags       []string `json:"tags"`       // 需要的标签
	Severity   []string `json:"severity"`   // 需要的严重程度
	Workflows  []string `json:"workflows"`  // 需要的workflow
}
