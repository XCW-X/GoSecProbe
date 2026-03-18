package model

import "time"

// AssetRecord 资产数据库记录模型
type AssetRecord struct {
	ID        int64     `json:"id"`
	Value     string    `json:"value"`      // IP 或域名
	AssetType string    `json:"asset_type"` // ip / domain
	IsAlive   bool      `json:"is_alive"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// AssetScanRecord 资产扫描结果数据库记录模型
type AssetScanRecord struct {
	ID        int64     `json:"id"`
	TaskID    int       `json:"task_id"`
	AssetID   int64     `json:"asset_id"`
	ScanType  string    `json:"scan_type"` // alive / port / web / vuln
	Status    string    `json:"status"`    // success / failed
	Result    string    `json:"result"`    // JSON格式的扫描结果
	ScannedAt time.Time `json:"scanned_at"`
}
