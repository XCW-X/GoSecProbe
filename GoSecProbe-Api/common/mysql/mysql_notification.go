package mysql

import (
	"database/sql"
	"time"
)

// VulnNotificationSummary 漏洞通知摘要
type VulnNotificationSummary struct {
	HasVuln     bool `json:"has_vuln"`     // 是否有未读漏洞
	HighCount   int  `json:"high_count"`   // 高危及以上未读漏洞数
	UnreadCount int  `json:"unread_count"` // 总未读漏洞数
}

// ensureNotificationRecord 确保用户有通知记录，不存在则插入
func ensureNotificationRecord(username string) {
	DB.Exec(`INSERT IGNORE INTO notification_read_time (username, last_read_at, last_cleared_at) VALUES (?, '2000-01-01 00:00:00', '2000-01-01 00:00:00')`, username)
}

// GetVulnNotificationSummary 获取用户的漏洞通知摘要（用于 Navbar Badge）
func GetVulnNotificationSummary(username string) (*VulnNotificationSummary, error) {
	ensureNotificationRecord(username)

	// 获取用户的已读时间和清空时间
	var lastReadAt, lastClearedAt time.Time
	err := DB.QueryRow(`SELECT last_read_at, last_cleared_at FROM notification_read_time WHERE username = ?`, username).
		Scan(&lastReadAt, &lastClearedAt)
	if err != nil {
		lastReadAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		lastClearedAt = lastReadAt
	}

	// 取 max(last_read_at, last_cleared_at) 作为基准时间
	baseTime := lastReadAt
	if lastClearedAt.After(baseTime) {
		baseTime = lastClearedAt
	}

	summary := &VulnNotificationSummary{}

	// 查询该用户任务下、基准时间之后发现的漏洞
	// 使用 COALESCE 防止无匹配行时 SUM 返回 NULL 导致 Scan 失败
	row := DB.QueryRow(`
		SELECT
			COUNT(*) as total,
			COALESCE(SUM(CASE WHEN v.severity IN ('critical','high') THEN 1 ELSE 0 END), 0) as high_count
		FROM vulnerability v
		INNER JOIN task t ON v.task_id = t.id
		WHERE t.creator = ? AND v.discovered_at > ?
	`, username, baseTime)

	var total, highCount int
	if err := row.Scan(&total, &highCount); err != nil {
		return summary, err
	}

	summary.UnreadCount = total
	summary.HighCount = highCount
	summary.HasVuln = total > 0

	return summary, nil
}

// GetRecentVulnNotifications 获取用户的最新漏洞通知列表
func GetRecentVulnNotifications(username string, limit int) (*sql.Rows, error) {
	ensureNotificationRecord(username)

	// 获取清空时间（清空后的漏洞不显示）
	var lastClearedAt time.Time
	DB.QueryRow(`SELECT last_cleared_at FROM notification_read_time WHERE username = ?`, username).Scan(&lastClearedAt)

	rows, err := DB.Query(`
		SELECT
			v.id, v.task_id, t.name as task_name,
			v.name as title, v.severity, v.target, v.description,
			v.discovered_at
		FROM vulnerability v
		INNER JOIN task t ON v.task_id = t.id
		WHERE t.creator = ? AND v.discovered_at > ?
		ORDER BY v.discovered_at DESC
		LIMIT ?
	`, username, lastClearedAt, limit)

	return rows, err
}

// MarkAllVulnNotificationsRead 将所有漏洞通知标记为已读（更新 last_read_at 为当前时间）
func MarkAllVulnNotificationsRead(username string) error {
	ensureNotificationRecord(username)
	_, err := DB.Exec(`UPDATE notification_read_time SET last_read_at = NOW() WHERE username = ?`, username)
	return err
}

// ClearVulnNotifications 清空通知（更新 last_cleared_at 为当前时间）
func ClearVulnNotifications(username string) error {
	ensureNotificationRecord(username)
	_, err := DB.Exec(`UPDATE notification_read_time SET last_cleared_at = NOW(), last_read_at = NOW() WHERE username = ?`, username)
	return err
}
