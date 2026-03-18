package mysql

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// SaveWebFingerprint 保存Web指纹到数据库
func SaveWebFingerprint(
	taskID int,
	assetID int64,
	portID *int64, // 可选，如果是从端口扫描触发的
	url, ip string,
	port int,
	protocol string,
	title string,
	statusCode int,
	server, contentType string,
	contentLength int64,
	responseTime int,
	technologies []string,
	frameworks []string,
	matchedRules []string,
	faviconHash string,
	headers map[string]string,
) error {
	// 将切片和map转换为JSON
	technologiesJSON, err := json.Marshal(technologies)
	if err != nil {
		return fmt.Errorf("序列化technologies失败: %v", err)
	}

	frameworksJSON, err := json.Marshal(frameworks)
	if err != nil {
		return fmt.Errorf("序列化frameworks失败: %v", err)
	}

	matchedRulesJSON, err := json.Marshal(matchedRules)
	if err != nil {
		return fmt.Errorf("序列化matchedRules失败: %v", err)
	}

	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return fmt.Errorf("序列化headers失败: %v", err)
	}

	query := `
		INSERT INTO asset_web_fingerprints (
			task_id, asset_id, port_id,
			url, ip, port, protocol,
			title, status_code, server, content_type, content_length, response_time,
			technologies, frameworks, matched_rules, favicon_hash, headers
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			title = VALUES(title),
			status_code = VALUES(status_code),
			server = VALUES(server),
			content_type = VALUES(content_type),
			content_length = VALUES(content_length),
			response_time = VALUES(response_time),
			technologies = VALUES(technologies),
			frameworks = VALUES(frameworks),
			matched_rules = VALUES(matched_rules),
			favicon_hash = VALUES(favicon_hash),
			headers = VALUES(headers),
			last_checked = NOW()
	`

	_, err = DB.Exec(
		query,
		taskID, assetID, portID,
		url, ip, port, protocol,
		title, statusCode, server, contentType, contentLength, responseTime,
		technologiesJSON, frameworksJSON, matchedRulesJSON, faviconHash, headersJSON,
	)

	return err
}

// GetWebFingerprintsByTaskID 根据任务ID获取Web指纹列表
func GetWebFingerprintsByTaskID(taskID int) (*sql.Rows, error) {
	query := `
		SELECT 
			wf.id, wf.task_id, wf.asset_id, wf.port_id,
			wf.url, wf.ip, wf.port, wf.protocol,
			wf.title, wf.status_code, wf.server, wf.content_type, wf.content_length, wf.response_time,
			wf.technologies, wf.frameworks, wf.matched_rules, wf.favicon_hash, wf.headers,
			wf.discovered_at, wf.last_checked
		FROM asset_web_fingerprints wf
		WHERE wf.task_id = ?
		ORDER BY wf.discovered_at DESC
	`
	return DB.Query(query, taskID)
}

// GetWebFingerprintsByAssetID 根据资产ID获取Web指纹列表
func GetWebFingerprintsByAssetID(assetID int64) (*sql.Rows, error) {
	query := `
		SELECT 
			wf.id, wf.task_id, wf.asset_id, wf.port_id,
			wf.url, wf.ip, wf.port, wf.protocol,
			wf.title, wf.status_code, wf.server, wf.content_type, wf.content_length, wf.response_time,
			wf.technologies, wf.frameworks, wf.matched_rules, wf.favicon_hash, wf.headers,
			wf.discovered_at, wf.last_checked
		FROM asset_web_fingerprints wf
		WHERE wf.asset_id = ?
		ORDER BY wf.discovered_at DESC
	`
	return DB.Query(query, assetID)
}

// DeleteWebFingerprintsByTaskID 删除指定任务的所有Web指纹记录
func DeleteWebFingerprintsByTaskID(taskID int) error {
	_, err := DB.Exec("DELETE FROM asset_web_fingerprints WHERE task_id = ?", taskID)
	return err
}

// GetHTTPPortsByTaskID 获取任务中所有HTTP/HTTPS端口
// 用于从端口扫描结果自动触发Web指纹识别
func GetHTTPPortsByTaskID(taskID int) (*sql.Rows, error) {
	query := `
		SELECT 
			id, ip, port, protocol, service_name
		FROM asset_port
		WHERE task_id = ?
		AND state = 'open'
		AND (
			-- 常见HTTP/HTTPS端口
			port IN (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000)
			-- 或者服务名包含http关键字
			OR LOWER(service_name) LIKE '%http%'
			OR LOWER(service_name) LIKE '%web%'
			OR LOWER(service_name) = 'ssl/http'
		)
		ORDER BY port
	`
	return DB.Query(query, taskID)
}
