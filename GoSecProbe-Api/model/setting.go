package model

// SystemSettings 系统设置结构体
type SystemSettings struct {
	ID          int    `json:"id"`
	NetworkCard string `json:"network_card"` // 选择的网卡名称
	Concurrency int    `json:"concurrency"`  // 扫描并发数
	Timeout     int    `json:"timeout"`      // 全局超时（秒）
	Retries     int    `json:"retries"`      // 重试次数
	ProxyType   string `json:"proxy_type"`   // 代理类型: "", "socks5", "http"
	ProxyURL    string `json:"proxy_url"`    // 代理地址, 例如: socks5://127.0.0.1:1080
	// 反连设置
	ReverseDnslogDomain string `json:"reverse_dnslog_domain"`
	ReverseRMIServer    string `json:"reverse_rmi_server"`
	ReverseLDAPServer   string `json:"reverse_ldap_server"`
	ReverseHTTPServer   string `json:"reverse_http_server"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

// NetworkInterface 网卡信息
type NetworkInterface struct {
	Name      string   `json:"name"`       // 网卡名称
	IPs       []string `json:"ips"`        // IP地址列表
	IsUp      bool     `json:"is_up"`      // 是否启用
	IsDefault bool     `json:"is_default"` // 是否默认网卡
}

// UpdateSettingsRequest 更新设置请求
type UpdateSettingsRequest struct {
	NetworkCard string `json:"network_card"`
	Concurrency int    `json:"concurrency" binding:"min=1,max=1000"`
	Timeout     int    `json:"timeout" binding:"min=1,max=300"`
	Retries     int    `json:"retries" binding:"min=0,max=10"`
	ProxyType   string `json:"proxy_type"`
	ProxyURL    string `json:"proxy_url"`
	// 反连设置
	ReverseDnslogDomain string `json:"reverse_dnslog_domain"`
	ReverseRMIServer    string `json:"reverse_rmi_server"`
	ReverseLDAPServer   string `json:"reverse_ldap_server"`
	ReverseHTTPServer   string `json:"reverse_http_server"`
}
