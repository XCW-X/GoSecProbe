package mysql

import (
	"database/sql"
	"fmt"
)

// ============================================
// 任务管理模块
// 说明: 处理扫描任务的增删改查、状态更新等操作
// ============================================

// CreateTask 创建扫描任务
func CreateTask(name, target, taskType, creator, description, options string) (int64, error) {
	result, err := DB.Exec(
		"INSERT INTO task (name, target, type, creator, description, options, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())",
		name, target, taskType, creator, description, options,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetTaskByID 根据ID查询任务
func GetTaskByID(taskID int) (*sql.Row, error) {
	query := `
	SELECT id, name, target, type, status, progress, creator, description, 
	       options, created_at, updated_at, started_at, completed_at
	FROM task WHERE id = ?`
	return DB.QueryRow(query, taskID), nil
}

// GetTaskList 获取任务列表（支持分页和筛选）
func GetTaskList(page, pageSize int, creator, status, name, taskType string) (*sql.Rows, int, error) {
	// 构建查询条件
	whereClause := "WHERE 1=1"
	args := make([]interface{}, 0)

	if creator != "" {
		whereClause += " AND creator = ?"
		args = append(args, creator)
	}
	if status != "" {
		whereClause += " AND status = ?"
		args = append(args, status)
	}
	if name != "" {
		whereClause += " AND name LIKE ?"
		args = append(args, "%"+name+"%")
	}
	if taskType != "" {
		whereClause += " AND type = ?"
		args = append(args, taskType)
	}

	// 查询总数
	var total int
	countQuery := "SELECT COUNT(*) FROM task " + whereClause
	err := DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// 查询列表
	offset := (page - 1) * pageSize
	query := `
	SELECT id, name, target, type, status, progress, creator, description, 
	       options, created_at, updated_at, started_at, completed_at
	FROM task ` + whereClause + ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, offset)

	rows, err := DB.Query(query, args...)
	return rows, total, err
}

// GetPendingScheduledTasks 获取所有处于 pending 状态的任务
func GetPendingScheduledTasks() (*sql.Rows, error) {
	query := `
	SELECT id, name, target, type, status, progress, creator, description, 
	       options, created_at, updated_at, started_at, completed_at
	FROM task WHERE status = 'pending'`
	return DB.Query(query)
}

// UpdateTaskStatus 更新任务状态
func UpdateTaskStatus(taskID int, status string, progress int) error {
	_, err := DB.Exec(
		"UPDATE task SET status = ?, progress = ?, updated_at = NOW() WHERE id = ?",
		status, progress, taskID,
	)
	return err
}

// UpdateTaskProgress 更新任务进度和状态（不再更新 result 字段）
// 扫描结果现在存储在 asset_scan_result 表中
func UpdateTaskProgress(taskID int, status string, progress int) error {
	query := `
	UPDATE task 
	SET status = ?, progress = ?, updated_at = NOW(),
	    created_at = IF(? = 'running' AND ? = 0, NOW(), created_at),
	    started_at = IF(? = 'running' AND ? = 0, NOW(), started_at),
	    completed_at = IF(? = 'running' AND ? = 0, NULL, IF(? IN ('completed', 'failed', 'stopped'), NOW(), completed_at))
	WHERE id = ?`

	_, err := DB.Exec(query, status, progress, status, progress, status, progress, status, progress, status, taskID)
	return err
}

// UpdateTaskResult 保持向后兼容（废弃，请使用 UpdateTaskProgress）
func UpdateTaskResult(taskID int, status string, progress int, _ string) error {
	return UpdateTaskProgress(taskID, status, progress)
}

// DeleteTask 删除任务（级联删除相关漏洞）
func DeleteTask(taskID int) error {
	_, err := DB.Exec("DELETE FROM task WHERE id = ?", taskID)
	return err
}

// GetTaskStats 获取任务统计信息
func GetTaskStats(creator string) (map[string]int, error) {
	stats := make(map[string]int)

	query := `
	SELECT 
		COUNT(*) as total,
		SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
		SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
		SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
		SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
	FROM task WHERE creator = ?`

	var total, pending, running, completed, failed int
	err := DB.QueryRow(query, creator).Scan(&total, &pending, &running, &completed, &failed)
	if err != nil {
		return stats, err
	}

	stats["total"] = total
	stats["pending"] = pending
	stats["running"] = running
	stats["completed"] = completed
	stats["failed"] = failed

	return stats, nil
}

// ============================================
// 任务筛选辅助函数
// ============================================

// GetTasksByCreatorWithFilter 根据创建者获取任务列表（支持筛选和分页）
func GetTasksByCreatorWithFilter(creator string, limit, offset int, name, status, taskType string) (*sql.Rows, error) {
	query := `SELECT id, name, target, type, status, progress, creator, description, 
			  options, created_at, updated_at, started_at, completed_at 
			  FROM task WHERE creator = ?`

	args := []interface{}{creator}

	// 添加名称筛选
	if name != "" {
		query += " AND name LIKE ?"
		args = append(args, "%"+name+"%")
	}

	// 添加状态筛选
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	// 添加类型筛选
	if taskType != "" {
		query += " AND type = ?"
		args = append(args, taskType)
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	return DB.Query(query, args...)
}

// CountTasksByCreatorWithFilter 统计用户的任务数量（支持筛选）
func CountTasksByCreatorWithFilter(creator, name, status, taskType string) (int, error) {
	query := "SELECT COUNT(*) FROM task WHERE creator = ?"
	args := []interface{}{creator}

	// 添加名称筛选
	if name != "" {
		query += " AND name LIKE ?"
		args = append(args, "%"+name+"%")
	}

	// 添加状态筛选
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	// 添加类型筛选
	if taskType != "" {
		query += " AND type = ?"
		args = append(args, taskType)
	}

	var count int
	err := DB.QueryRow(query, args...).Scan(&count)
	return count, err
}

// ClearTaskResults 清除任务的所有扫描结果（用于重新扫描）
func ClearTaskResults(taskID int) error {
	// 开启事务
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("开启事务失败: %v", err)
	}
	defer tx.Rollback()

	// 1. 删除 asset_scan_result 表中该任务的所有记录
	_, err = tx.Exec("DELETE FROM asset_scan_result WHERE task_id = ?", taskID)
	if err != nil {
		return fmt.Errorf("删除扫描结果失败: %v", err)
	}

	// 2. 删除 asset_port 表中该任务的所有记录
	_, err = tx.Exec("DELETE FROM asset_port WHERE task_id = ?", taskID)
	if err != nil {
		return fmt.Errorf("删除端口信息失败: %v", err)
	}

	// 3. 删除 asset_web_fingerprints 表中该任务的所有记录
	_, err = tx.Exec("DELETE FROM asset_web_fingerprints WHERE task_id = ?", taskID)
	if err != nil {
		return fmt.Errorf("删除Web指纹失败: %v", err)
	}

	// 4. 提交事务
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %v", err)
	}

	return nil
}
