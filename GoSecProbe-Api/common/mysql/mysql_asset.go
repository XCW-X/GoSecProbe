package mysql

import (
	"database/sql"
	"time"
)

// ============================================
// 资产管理模块
// 说明: 处理资产的增删改查操作
// ============================================

// CreateOrUpdateAsset 创建或更新资产
func CreateOrUpdateAsset(value, assetType string, isAlive bool) (int64, error) {
	now := time.Now()

	// 先尝试查找已存在的资产
	var id int64
	err := DB.QueryRow("SELECT id FROM asset WHERE value = ?", value).Scan(&id)

	if err == sql.ErrNoRows {
		// 资产不存在，创建新资产
		result, err := DB.Exec(
			`INSERT INTO asset (value, asset_type, is_alive, first_seen, last_seen) 
			 VALUES (?, ?, ?, ?, ?)`,
			value, assetType, isAlive, now, now,
		)
		if err != nil {
			return 0, err
		}
		return result.LastInsertId()
	} else if err != nil {
		return 0, err
	}

	// 资产已存在，更新信息
	_, err = DB.Exec(
		`UPDATE asset SET is_alive = ?, last_seen = ?, asset_type = ? WHERE id = ?`,
		isAlive, now, assetType, id,
	)
	if err != nil {
		return 0, err
	}

	return id, nil
}

// GetOrCreateAsset 获取或创建资产（CreateOrUpdateAsset的别名）
// 如果资产不存在则创建，存在则返回ID
func GetOrCreateAsset(value, assetType string) (int64, error) {
	return CreateOrUpdateAsset(value, assetType, false)
}

// GetAssetByValue 根据值获取资产
func GetAssetByValue(value string) (*sql.Row, error) {
	query := "SELECT id, value, asset_type, is_alive, first_seen, last_seen FROM asset WHERE value = ?"
	return DB.QueryRow(query, value), nil
}

// GetAssetByID 根据ID获取资产
func GetAssetByID(id int64) (*sql.Row, error) {
	query := "SELECT id, value, asset_type, is_alive, first_seen, last_seen FROM asset WHERE id = ?"
	return DB.QueryRow(query, id), nil
}

// GetAllAssets 获取所有资产列表（支持分页）
func GetAllAssets(page, pageSize int, assetType string, isAlive *bool) (*sql.Rows, int, error) {
	whereClause := "WHERE 1=1"
	args := make([]interface{}, 0)

	if assetType != "" {
		whereClause += " AND asset_type = ?"
		args = append(args, assetType)
	}

	if isAlive != nil {
		whereClause += " AND is_alive = ?"
		args = append(args, *isAlive)
	}

	// 查询总数
	var total int
	countQuery := "SELECT COUNT(*) FROM asset " + whereClause
	err := DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// 查询列表
	offset := (page - 1) * pageSize
	query := `SELECT id, value, asset_type, is_alive, first_seen, last_seen 
			  FROM asset ` + whereClause + ` ORDER BY last_seen DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, offset)

	rows, err := DB.Query(query, args...)
	return rows, total, err
}

// DeleteAsset 删除资产
func DeleteAsset(id int64) error {
	_, err := DB.Exec("DELETE FROM asset WHERE id = ?", id)
	return err
}

// ============================================
// 资产扫描结果管理
// ============================================

// SaveAssetScanResult 保存资产扫描结果
func SaveAssetScanResult(taskID int, assetID int64, scanType, status, result string) error {
	_, err := DB.Exec(
		`INSERT INTO asset_scan_result (task_id, asset_id, scan_type, status, result, scanned_at) 
		 VALUES (?, ?, ?, ?, ?, NOW())`,
		taskID, assetID, scanType, status, result,
	)
	return err
}

// GetAssetScanResultsByTaskID 根据任务ID获取扫描结果
func GetAssetScanResultsByTaskID(taskID int) (*sql.Rows, error) {
	query := `
	SELECT asr.id, asr.task_id, asr.asset_id, asr.scan_type, asr.status, asr.result, asr.scanned_at,
	       a.value, a.asset_type, a.is_alive
	FROM asset_scan_result asr
	LEFT JOIN asset a ON asr.asset_id = a.id
	WHERE asr.task_id = ?
	ORDER BY asr.scanned_at DESC`

	return DB.Query(query, taskID)
}

// GetAssetScanResultByID 根据ID获取单个扫描结果
func GetAssetScanResultByID(id int64) (*sql.Row, error) {
	query := `
	SELECT asr.id, asr.task_id, asr.asset_id, asr.scan_type, asr.status, asr.result, asr.scanned_at,
	       a.value, a.asset_type, a.is_alive
	FROM asset_scan_result asr
	LEFT JOIN asset a ON asr.asset_id = a.id
	WHERE asr.id = ?`

	return DB.QueryRow(query, id), nil
}

// DeleteAssetScanResultsByTaskID 删除任务的所有扫描结果
func DeleteAssetScanResultsByTaskID(taskID int) error {
	_, err := DB.Exec("DELETE FROM asset_scan_result WHERE task_id = ?", taskID)
	return err
}

// GetAssetScanStats 获取资产扫描统计信息
func GetAssetScanStats(taskID int) (map[string]int, error) {
	stats := make(map[string]int)

	query := `
	SELECT 
		COUNT(*) as total,
		SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success,
		SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
		SUM(CASE WHEN a.is_alive = TRUE THEN 1 ELSE 0 END) as alive
	FROM asset_scan_result asr
	LEFT JOIN asset a ON asr.asset_id = a.id
	WHERE asr.task_id = ?`

	var total, success, failed, alive int
	err := DB.QueryRow(query, taskID).Scan(&total, &success, &failed, &alive)
	if err != nil {
		return stats, err
	}

	stats["total"] = total
	stats["success"] = success
	stats["failed"] = failed
	stats["alive"] = alive

	return stats, nil
}
