package scanweb

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"fmt"
)

// SaveWebFingerprintToDB 保存Web指纹到数据库
// 将Web指纹结果保存到 asset_web_fingerprints 表
// portID: 可选参数，如果是从端口扫描触发的，传入对应的 port_id
func SaveWebFingerprintToDB(taskID int, fingerprint *WebFingerprint, portID *int64) error {
	// 1. 首先确保资产记录存在
	assetID, err := mysql.GetOrCreateAsset(fingerprint.IP, "ip")
	if err != nil {
		log.Info("[Web扫描] 创建或获取资产失败: %v", err)
		return fmt.Errorf("创建或获取资产失败: %v", err)
	}

	// 2. 确定协议
	protocol := "http"
	if fingerprint.Port == 443 || fingerprint.Port == 8443 {
		protocol = "https"
	}

	// 3. 调用MySQL函数保存
	err = mysql.SaveWebFingerprint(
		taskID,
		assetID,
		portID, // 关联的端口ID（可为nil）
		fingerprint.URL,
		fingerprint.IP,
		fingerprint.Port,
		protocol,
		fingerprint.Title,
		fingerprint.StatusCode,
		fingerprint.Server,
		fingerprint.ContentType,
		fingerprint.ContentLength,
		int(fingerprint.ResponseTime),
		fingerprint.Technologies,
		fingerprint.Frameworks,
		fingerprint.MatchedRules,
		fingerprint.FaviconHash,
		fingerprint.Headers,
	)

	if err != nil {
		return fmt.Errorf("保存Web指纹失败: %v", err)
	}

	// 输出详细指纹识别日志
	var parts []string
	if len(fingerprint.Technologies) > 0 {
		parts = append(parts, fmt.Sprintf("技术栈[Wappalyzer]=%v", fingerprint.Technologies))
	}
	if len(fingerprint.Frameworks) > 0 {
		parts = append(parts, fmt.Sprintf("框架[GoSecProbe]=%v", fingerprint.Frameworks))
	}
	if len(fingerprint.MatchedRules) > 0 {
		parts = append(parts, fmt.Sprintf("命中規则=%v", fingerprint.MatchedRules))
	}
	if fingerprint.Server != "" {
		parts = append(parts, fmt.Sprintf("Server=%s", fingerprint.Server))
	}
	if fingerprint.Title != "" {
		parts = append(parts, fmt.Sprintf("标题=%s", fingerprint.Title))
	}

	detailStr := "无命中指纹"
	if len(parts) > 0 {
		detailStr = fmt.Sprintf("%s", join(parts, " | "))
	}

	log.Info("[Web扫描] 已保存: %s (HTTP %d, %dms) -> %s",
		fingerprint.URL, fingerprint.StatusCode, fingerprint.ResponseTime, detailStr)

	return nil
}

// join 内部字符串拼接辅助函数
func join(items []string, sep string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += sep
		}
		result += item
	}
	return result
}

// BuildURLsFromPorts 根据开放的HTTP端口构建URL列表
// 从端口扫描结果中提取HTTP/HTTPS服务，构建待扫描的URL列表
func BuildURLsFromPorts(host string, ports []PortInfo) []string {
	urls := make([]string, 0)

	for _, portInfo := range ports {
		if !portInfo.IsOpen {
			continue
		}

		// 判断是否为Web服务
		serviceName := portInfo.ServiceName
		isHTTPS := false

		// 常见的HTTPS端口和服务名
		if portInfo.Port == 443 || portInfo.Port == 8443 ||
			serviceName == "https" || serviceName == "ssl/http" {
			isHTTPS = true
		}

		// 常见的HTTP端口和服务名
		isHTTP := portInfo.Port == 80 || portInfo.Port == 8080 || portInfo.Port == 8000 ||
			portInfo.Port == 8888 || portInfo.Port == 3000 ||
			serviceName == "http" || serviceName == "http-proxy" ||
			serviceName == "http-alt"

		// 如果服务名包含http关键字
		if !isHTTP && !isHTTPS {
			lowerService := serviceName
			if len(lowerService) > 0 {
				if containsAny(lowerService, []string{"http", "web", "www"}) {
					isHTTP = true
				}
			}
		}

		// 构建URL
		if isHTTPS {
			if portInfo.Port == 443 {
				urls = append(urls, fmt.Sprintf("https://%s", host))
			} else {
				urls = append(urls, fmt.Sprintf("https://%s:%d", host, portInfo.Port))
			}
		} else if isHTTP {
			if portInfo.Port == 80 {
				urls = append(urls, fmt.Sprintf("http://%s", host))
			} else {
				urls = append(urls, fmt.Sprintf("http://%s:%d", host, portInfo.Port))
			}
		}
	}

	return urls
}

// PortInfo 端口信息结构（用于从端口扫描结果构建URL）
type PortInfo struct {
	Port        int
	IsOpen      bool
	ServiceName string
}

// containsAny 检查字符串是否包含任意一个子串
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(substr) > 0 && len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
