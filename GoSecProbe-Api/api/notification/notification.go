package notification

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"database/sql"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes 注册通知相关路由
func RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/notification/unread", GetUnreadNotification) // 获取未读漏洞通知摘要
	r.POST("/notification/read-all", MarkAllRead)        // 一键已读
	r.DELETE("/notification/clear", ClearNotifications)  // 清空通知
	r.GET("/notification/list", GetNotificationList)     // 获取通知列表
}

// NotificationSummary Navbar红点数据
type NotificationSummary struct {
	HasVuln     bool `json:"has_vuln"`     // 是否存在漏洞（用于红点）
	HighCount   int  `json:"high_count"`   // 高危及以上漏洞数（用于数字徽标）
	UnreadCount int  `json:"unread_count"` // 未读通知总数
}

// NotificationItem 通知列表项
type NotificationItem struct {
	ID           int    `json:"id"`
	VulnID       int    `json:"vuln_id"`
	TaskID       int    `json:"task_id"`
	TaskName     string `json:"task_name"`
	Title        string `json:"title"`
	Content      string `json:"content"`
	Severity     string `json:"severity"`
	Target       string `json:"target"`
	IsRead       bool   `json:"is_read"`
	DiscoveredAt string `json:"discovered_at"`
}

// GetUnreadNotification 获取未读通知摘要（供 Navbar Badge 使用）
func GetUnreadNotification(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{"code": 40100, "msg": "未认证用户", "data": nil})
		return
	}

	// 查询该用户任务下的漏洞数量
	summary, err := mysql.GetVulnNotificationSummary(username.(string))
	if err != nil {
		log.Info("[Notification] 获取摘要失败: %v", err)
		c.JSON(500, gin.H{"code": 50000, "msg": "获取通知摘要失败", "data": nil})
		return
	}

	c.JSON(200, gin.H{"code": 20000, "msg": "ok", "data": summary})
}

// GetNotificationList 获取通知列表
func GetNotificationList(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{"code": 40100, "msg": "未认证用户", "data": nil})
		return
	}

	pageSizeStr := c.DefaultQuery("pageSize", "20")
	pageSize, _ := strconv.Atoi(pageSizeStr)
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	rows, err := mysql.GetRecentVulnNotifications(username.(string), pageSize)
	if err != nil {
		log.Info("[Notification] 获取列表失败: %v", err)
		c.JSON(500, gin.H{"code": 50000, "msg": "获取通知列表失败", "data": nil})
		return
	}
	defer rows.Close()

	items := []NotificationItem{}
	for rows.Next() {
		var item NotificationItem
		var discoveredAt time.Time
		var taskName sql.NullString

		err := rows.Scan(
			&item.VulnID, &item.TaskID, &taskName,
			&item.Title, &item.Severity, &item.Target, &item.Content,
			&discoveredAt,
		)
		if err != nil {
			log.Info("[Notification] 解析行失败: %v", err)
			continue
		}
		item.ID = item.VulnID
		item.TaskName = taskName.String
		item.DiscoveredAt = discoveredAt.Format("2006-01-02 15:04:05")
		item.IsRead = false
		items = append(items, item)
	}

	c.JSON(200, gin.H{"code": 20000, "msg": "ok", "data": items})
}

// MarkAllRead 一键已读（前端本地状态管理，后端记录时间戳）
func MarkAllRead(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{"code": 40100, "msg": "未认证用户", "data": nil})
		return
	}

	err := mysql.MarkAllVulnNotificationsRead(username.(string))
	if err != nil {
		log.Info("[Notification] 标记已读失败: %v", err)
		c.JSON(500, gin.H{"code": 50000, "msg": "标记已读失败", "data": nil})
		return
	}

	c.JSON(200, gin.H{"code": 20000, "msg": "已全部标记为已读", "data": nil})
}

// ClearNotifications 清空通知（重置已读时间戳为 now，不删除漏洞本身）
func ClearNotifications(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(401, gin.H{"code": 40100, "msg": "未认证用户", "data": nil})
		return
	}

	err := mysql.ClearVulnNotifications(username.(string))
	if err != nil {
		log.Info("[Notification] 清空通知失败: %v", err)
		c.JSON(500, gin.H{"code": 50000, "msg": "清空通知失败", "data": nil})
		return
	}

	c.JSON(200, gin.H{"code": 20000, "msg": "通知已清空", "data": nil})
}
