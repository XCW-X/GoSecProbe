package scanweb

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"GoSecProbe/service/common"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ScanWebFingerprintsFromPorts 从端口扫描结果触发 Web 指纹识别
// targets: 原始扫描目标，用于提取域名信息以便在URL中使用域名而非IP
func ScanWebFingerprintsFromPorts(ctx context.Context, taskID int, targets []*common.Target) error {
	log.Info("[Web扫描] 开始为任务 #%d 进行Web指纹识别", taskID)

	// 1. 构建 IP 到原始目标的映射，优先保留包含域名的目标
	ipToTargets := make(map[string][]*common.Target)
	for _, t := range targets {
		if t.IP != "" {
			ipToTargets[t.IP] = append(ipToTargets[t.IP], t)
		}
	}

	// 2. 查询所有HTTP/HTTPS端口
	rows, err := mysql.GetHTTPPortsByTaskID(taskID)
	if err != nil {
		return fmt.Errorf("查询HTTP端口失败: %v", err)
	}
	defer rows.Close()

	// 3. 创建Web扫描器
	scanner, err := NewWebScanner(15 * time.Second)
	if err != nil {
		return fmt.Errorf("创建Web扫描器失败: %v", err)
	}

	// 4. 收集需要扫描的URL
	type PortRecord struct {
		ID          int64
		IP          string
		Port        int
		Protocol    string
		ServiceName string
	}

	var portRecords []PortRecord
	for rows.Next() {
		var pr PortRecord
		err := rows.Scan(&pr.ID, &pr.IP, &pr.Port, &pr.Protocol, &pr.ServiceName)
		if err != nil {
			log.Info("[Web扫描] 解析端口记录失败: %v", err)
			continue
		}
		portRecords = append(portRecords, pr)
	}

	if len(portRecords) == 0 {
		log.Info("[Web扫描] 任务 #%d 没有发现HTTP/HTTPS服务", taskID)
		return nil
	}

	// 5. 逐个处理每个端口
	successCount := 0

	for _, pr := range portRecords {
		// 确定需要扫描的基准主机名/IP
		scanHosts := []string{pr.IP}
		preferredURLs := []string{}

		// 如果该 IP 关联了域名，则优先使用域名
		if associatedTargets, ok := ipToTargets[pr.IP]; ok {
			for _, t := range associatedTargets {
				// 如果原始输入本身就是 URL，且端口匹配，则将其加入优先扫描列表
				if strings.HasPrefix(strings.ToLower(t.Original), "http") {
					// 只有当 URL 的端口与当前扫描端口一致，或者为默认端口时才加入
					// 这里简化处理：如果是 80/443 且 URL 中没显式写端口，或者显式端口匹配
					preferredURLs = append(preferredURLs, t.Original)
				} else if t.Host != "" && t.Host != pr.IP {
					// 如果是域名且不是 IP，加入主机名列表
					found := false
					for _, h := range scanHosts {
						if h == t.Host {
							found = true
							break
						}
					}
					if !found {
						scanHosts = append([]string{t.Host}, scanHosts...) // 域名放在前面优先级更高
					}
				}
			}
		}

		// 构建最终待扫描的 URL 列表（去重）
		urlsToScan := make([]string, 0)
		urlSeen := make(map[string]bool)

		// 1. 优先使用原始输入的完整 URL
		for _, u := range preferredURLs {
			if !urlSeen[u] {
				urlsToScan = append(urlsToScan, u)
				urlSeen[u] = true
			}
		}

		// 2. 使用主机名/IP 构造默认 URL
		for _, host := range scanHosts {
			var baseDir string // 如果是域名且原始输入包含路径，这里可以扩展，目前先扫根目录

			isHTTPS := pr.Port == 443 || pr.Port == 8443 ||
				pr.ServiceName == "https" || pr.ServiceName == "ssl/http"

			var urlStr string
			if isHTTPS {
				if pr.Port == 443 {
					urlStr = fmt.Sprintf("https://%s%s", host, baseDir)
				} else {
					urlStr = fmt.Sprintf("https://%s:%d%s", host, pr.Port, baseDir)
				}
			} else {
				if pr.Port == 80 {
					urlStr = fmt.Sprintf("http://%s%s", host, baseDir)
				} else {
					urlStr = fmt.Sprintf("http://%s:%d%s", host, pr.Port, baseDir)
				}
			}

			if !urlSeen[urlStr] {
				urlsToScan = append(urlsToScan, urlStr)
				urlSeen[urlStr] = true
			}
		}

		// 执行扫描
		for _, url := range urlsToScan {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			log.Info("[Web扫描] 正在扫描: %s", url)
			fingerprint, err := scanner.ScanURL(ctx, url)
			if err != nil {
				log.Info("[Web扫描] 扫描 %s 失败: %v", url, err)
				continue
			}

			// 保存结果
			portID := pr.ID
			err = SaveWebFingerprintToDB(taskID, fingerprint, &portID)
			if err != nil {
				log.Info("[Web扫描] 保存 %s 结果失败: %v", url, err)
				continue
			}
			successCount++
		}
	}

	log.Info("[Web扫描] 任务 #%d 完成 - 成功识别 %d 个指纹点", taskID, successCount)
	return nil
}

// ScanGobusterDiscoveredURLs 对 Gobuster 发现的目录路径执行 Web 指纹识别
// 从数据库读取本次任务中由 Gobuster 扫描出的 URL（server 包含目录扫描字样），逐一进行指纹识别
func ScanGobusterDiscoveredURLs(ctx context.Context, taskID int) error {
	log.Info("[Web扫描] 开始对 Gobuster 发现路径进行指纹识别，任务 #%d", taskID)

	rows, err := mysql.GetWebFingerprintsByTaskID(taskID)
	if err != nil {
		return fmt.Errorf("读取Gobuster指纹记录失败: %v", err)
	}
	defer rows.Close()

	scanner, err := NewWebScanner(15 * time.Second)
	if err != nil {
		return fmt.Errorf("创建Web扫描器失败: %v", err)
	}

	type gobusterRecord struct {
		url     string
		assetID int64
	}

	var records []gobusterRecord
	for rows.Next() {
		var (
			id, assetID, statusCode, length, responseTime        int64
			portIDArr                                            sql.NullInt64
			taskIDVal, port                                      int
			url, ip, protocol                                    string
			title, server, contentType, fav                      sql.NullString
			techJSON, frameworksJSON, matchedRulesJSON, headJSON sql.NullString
			discoveredAt, lastChecked                            time.Time
		)
		if err := rows.Scan(
			&id, &taskIDVal, &assetID, &portIDArr,
			&url, &ip, &port, &protocol,
			&title, &statusCode, &server, &contentType, &length, &responseTime,
			&techJSON, &frameworksJSON, &matchedRulesJSON, &fav, &headJSON,
			&discoveredAt, &lastChecked,
		); err != nil {
			continue
		}
		// 只对 Gobuster 发现的目录路径进行指纹识别
		if server.Valid && strings.Contains(server.String, "目录扫描") {
			records = append(records, gobusterRecord{url: url, assetID: assetID})
		}
	}

	if len(records) == 0 {
		log.Info("[Web扫描] 没有找到 Gobuster 目录扫描结果可进行指纹识别，任务 #%d", taskID)
		return nil
	}

	successCount := 0
	for _, rec := range records {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Info("[Web扫描] 对 Gobuster 发现路径进行指纹识别: %s", rec.url)
		fingerprint, err := scanner.ScanURL(ctx, rec.url)
		if err != nil {
			log.Info("[Web扫描] 指纹识别 %s 失败: %v", rec.url, err)
			continue
		}

		// 使用 Gobuster 记录的 assetID 保存
		if err := SaveWebFingerprintToDB(taskID, fingerprint, nil); err != nil {
			log.Info("[Web扫描] 保存 Gobuster 路径指纹失败 %s: %v", rec.url, err)
			continue
		}
		successCount++
	}

	log.Info("[Web扫描] Gobuster 路径指纹识别完成，任务 #%d - 共识别 %d 条", taskID, successCount)
	return nil
}

// GetWebFingerprintsForTask 获取任务的所有Web指纹结果
func GetWebFingerprintsForTask(taskID int) ([]WebFingerprint, error) {
	rows, err := mysql.GetWebFingerprintsByTaskID(taskID)
	if err != nil {
		return nil, fmt.Errorf("查询Web指纹失败: %v", err)
	}
	defer rows.Close()

	var fingerprints []WebFingerprint
	for rows.Next() {
		var (
			id, assetID      int64
			portID           sql.NullInt64
			taskIDVal        int
			url, ip          string
			port             int
			protocol         string
			title, server    sql.NullString
			statusCode       sql.NullInt64
			contentType      sql.NullString
			contentLength    sql.NullInt64
			responseTime     sql.NullInt64
			technologiesJSON sql.NullString
			frameworksJSON   sql.NullString
			faviconHash      sql.NullString
			headersJSON      sql.NullString
			discoveredAt     time.Time
			lastChecked      time.Time
		)

		err := rows.Scan(
			&id, &taskIDVal, &assetID, &portID,
			&url, &ip, &port, &protocol,
			&title, &statusCode, &server, &contentType, &contentLength, &responseTime,
			&technologiesJSON, &frameworksJSON, &faviconHash, &headersJSON,
			&discoveredAt, &lastChecked,
		)

		if err != nil {
			log.Info("[Web扫描] 解析Web指纹记录失败: %v", err)
			continue
		}

		fp := WebFingerprint{
			URL:          url,
			IP:           ip,
			Port:         port,
			ResponseTime: responseTime.Int64,
		}

		if title.Valid {
			fp.Title = title.String
		}
		if statusCode.Valid {
			fp.StatusCode = int(statusCode.Int64)
		}
		if server.Valid {
			fp.Server = server.String
		}
		if contentType.Valid {
			fp.ContentType = contentType.String
		}
		if contentLength.Valid {
			fp.ContentLength = contentLength.Int64
		}
		if faviconHash.Valid {
			fp.FaviconHash = faviconHash.String
		}

		// 解析JSON字段
		if technologiesJSON.Valid && technologiesJSON.String != "" {
			var techs []string
			if err := json.Unmarshal([]byte(technologiesJSON.String), &techs); err == nil {
				fp.Technologies = techs
			}
		}

		if frameworksJSON.Valid && frameworksJSON.String != "" {
			var fws []string
			if err := json.Unmarshal([]byte(frameworksJSON.String), &fws); err == nil {
				fp.Frameworks = fws
			}
		}

		if headersJSON.Valid && headersJSON.String != "" {
			var headers map[string]string
			if err := json.Unmarshal([]byte(headersJSON.String), &headers); err == nil {
				fp.Headers = headers
			}
		}

		fingerprints = append(fingerprints, fp)
	}

	return fingerprints, nil
}
