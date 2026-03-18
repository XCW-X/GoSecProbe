package setting

import (
	"GoSecProbe/common/mysql"
	"net"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes 注册设置相关路由
func RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/setting", GetSettings)              // 获取系统设置
	r.POST("/setting", UpdateSettings)          // 更新系统设置
	r.GET("/setting/interfaces", GetInterfaces) // 获取网卡列表
}

// GetSettings 获取系统设置
func GetSettings(c *gin.Context) {
	settings, err := mysql.GetSettings()
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取系统设置失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "Success",
		"data": settings,
	})
}

// UpdateSettingsRequest 更新系统设置请求
type UpdateSettingsRequest struct {
	NetworkCard         string `json:"network_card"`
	Concurrency         int    `json:"concurrency"`
	Timeout             int    `json:"timeout"`
	Retries             int    `json:"retries"`
	ProxyType           string `json:"proxy_type"`
	ProxyURL            string `json:"proxy_url"`
	ReverseDnslogDomain string `json:"reverse_dnslog_domain"`
	ReverseDnslogAPI    string `json:"reverse_dnslog_api"`
	ReverseRMIServer    string `json:"reverse_rmi_server"`
	ReverseLDAPServer   string `json:"reverse_ldap_server"`
	ReverseHTTPServer   string `json:"reverse_http_server"`
}

// UpdateSettings 更新系统设置
func UpdateSettings(c *gin.Context) {
	var req UpdateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 验证代理类型
	if req.ProxyType != "" && req.ProxyType != "socks5" && req.ProxyType != "http" {
		c.JSON(400, gin.H{
			"code": 40001,
			"msg":  "代理类型必须为空、socks5或http",
			"data": nil,
		})
		return
	}

	// 验证代理URL格式
	if req.ProxyType != "" && req.ProxyURL == "" {
		c.JSON(400, gin.H{
			"code": 40002,
			"msg":  "设置代理类型后，代理地址不能为空",
			"data": nil,
		})
		return
	}

	// 构建设置结构体
	settings := &mysql.SystemSettings{
		ID:                  1, // 总是更新 ID=1
		NetworkCard:         req.NetworkCard,
		Concurrency:         req.Concurrency,
		Timeout:             req.Timeout,
		Retries:             req.Retries,
		ProxyType:           req.ProxyType,
		ProxyURL:            req.ProxyURL,
		ReverseDnslogDomain: req.ReverseDnslogDomain,
		ReverseDnslogAPI:    req.ReverseDnslogAPI,
		ReverseRMIServer:    req.ReverseRMIServer,
		ReverseLDAPServer:   req.ReverseLDAPServer,
		ReverseHTTPServer:   req.ReverseHTTPServer,
	}

	err := mysql.UpdateSettings(settings)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "更新系统设置失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "更新成功",
		"data": nil,
	})
}

// GetInterfaces 获取系统网卡列表
func GetInterfaces(c *gin.Context) {
	interfaces, err := net.Interfaces()
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取网卡列表失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	result := make([]map[string]interface{}, 0)
	for _, iface := range interfaces {
		// 获取该接口的地址列表
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// 构建地址列表
		ips := make([]string, 0)
		for _, addr := range addrs {
			// 过滤掉回环地址
			if ipnet, ok := addr.(*net.IPNet); ok {
				ips = append(ips, ipnet.IP.String())
			}
		}

		// 只添加有地址的接口
		if len(ips) > 0 {
			ifaceInfo := map[string]interface{}{
				"name":  iface.Name,
				"ips":   ips,
				"is_up": iface.Flags&net.FlagUp != 0,
			}
			result = append(result, ifaceInfo)
		}
	}

	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "Success",
		"data": result,
	})
}
