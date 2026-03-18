package task

import (
	"GoSecProbe/common/mysql"
	"GoSecProbe/common/redis"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetTaskRealtimeProgress 获取任务实时进度
// 优先从Redis获取实时进度，如果Redis没有则从MySQL获取
func GetTaskRealtimeProgress(c *gin.Context) {
	// 从URL参数获取任务ID
	taskIDStr := c.Param("id")
	taskID, err := strconv.Atoi(taskIDStr)
	if err != nil {
		c.JSON(400, gin.H{
			"code": 40000,
			"msg":  "无效的任务ID",
			"data": nil,
		})
		return
	}

	// 1. 先尝试从Redis获取实时进度
	redisProgress, err := redis.GetTaskProgress(taskID)
	if err != nil {
		// Redis查询失败，记录日志但继续
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取实时进度失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 2. 如果Redis有数据，优先使用Redis数据（实时）
	if redisProgress != nil {
		c.JSON(200, gin.H{
			"code": 20000,
			"msg":  "获取实时进度成功",
			"data": gin.H{
				"task_id":          redisProgress.TaskID,
				"status":           redisProgress.Status,
				"progress":         redisProgress.Progress,
				"total_targets":    redisProgress.TotalTargets,
				"scanned_targets":  redisProgress.ScannedTargets,
				"found_assets":     redisProgress.FoundAssets,
				"current_target":   redisProgress.CurrentTarget,
				"start_time":       redisProgress.StartTime,
				"last_update_time": redisProgress.LastUpdateTime,
				"message":          redisProgress.Message,
				"source":           "redis", // 标识数据来源
			},
		})
		return
	}

	// 3. Redis没有数据，从MySQL获取（任务已完成或未开始）
	row, err := mysql.GetTaskByID(taskID)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "查询任务失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	var task struct {
		Status   string
		Progress int
	}
	err = row.Scan(
		new(int), new(string), new(string), new(string),
		&task.Status, &task.Progress,
		new(string), new(interface{}), new(interface{}),
		new(interface{}), new(interface{}), new(interface{}), new(interface{}),
	)
	if err != nil {
		c.JSON(500, gin.H{
			"code": 50000,
			"msg":  "获取任务信息失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	// 返回MySQL数据
	c.JSON(200, gin.H{
		"code": 20000,
		"msg":  "获取进度成功",
		"data": gin.H{
			"task_id":  taskID,
			"status":   task.Status,
			"progress": task.Progress,
			"source":   "mysql", // 标识数据来源
		},
	})
}
