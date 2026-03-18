package model

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

// AssetPort 端口资产模型
type AssetPort struct {
	ID      int64  `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	TaskID  int    `gorm:"column:task_id;not null" json:"task_id"`
	AssetID *int64 `gorm:"column:asset_id" json:"asset_id,omitempty"`

	// 目标信息
	IP       string `gorm:"column:ip;not null;size:45" json:"ip"`
	Port     int    `gorm:"column:port;not null" json:"port"`
	Protocol string `gorm:"column:protocol;default:tcp;size:10" json:"protocol"`
	State    string `gorm:"column:state;default:open;size:20" json:"state"`

	// 服务信息
	ServiceName       string `gorm:"column:service_name;size:100" json:"service_name,omitempty"`
	ServiceProduct    string `gorm:"column:service_product;size:255" json:"service_product,omitempty"`
	ServiceVersion    string `gorm:"column:service_version;size:100" json:"service_version,omitempty"`
	ServiceExtraInfo  string `gorm:"column:service_extra_info;type:text" json:"service_extra_info,omitempty"`
	ServiceHostname   string `gorm:"column:service_hostname;size:255" json:"service_hostname,omitempty"`
	ServiceOSType     string `gorm:"column:service_os_type;size:100" json:"service_os_type,omitempty"`
	ServiceDeviceType string `gorm:"column:service_device_type;size:100" json:"service_device_type,omitempty"`
	ServiceConfidence int    `gorm:"column:service_confidence;default:0" json:"service_confidence"`

	// 指纹信息
	Banner            string `gorm:"column:banner;type:text" json:"banner,omitempty"`
	FingerprintMethod string `gorm:"column:fingerprint_method;size:50" json:"fingerprint_method,omitempty"`
	RawResponse       string `gorm:"column:raw_response;type:longtext" json:"raw_response,omitempty"`

	// CPE信息
	CPEs JSONStringArray `gorm:"column:cpes;type:json" json:"cpes,omitempty"`

	// 脚本扫描结果
	Scripts JSONMap `gorm:"column:scripts;type:json" json:"scripts,omitempty"`

	// 时间戳
	DiscoveredAt time.Time `gorm:"column:discovered_at;autoCreateTime" json:"discovered_at"`
	LastSeen     time.Time `gorm:"column:last_seen;autoUpdateTime" json:"last_seen"`
}

// TableName 指定表名
func (AssetPort) TableName() string {
	return "asset_port"
}

// JSONStringArray 字符串数组类型（用于JSON列）
type JSONStringArray []string

// Scan 实现 sql.Scanner 接口
func (j *JSONStringArray) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, j)
}

// Value 实现 driver.Valuer 接口
func (j JSONStringArray) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// JSONMap map类型（用于JSON列）
type JSONMap map[string]string

// Scan 实现 sql.Scanner 接口
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, j)
}

// Value 实现 driver.Valuer 接口
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// AssetPortSummary 端口资产统计摘要
type AssetPortSummary struct {
	TotalPorts      int            `json:"total_ports"`
	OpenPorts       int            `json:"open_ports"`
	ServiceCounts   map[string]int `json:"service_counts"`
	TopPorts        []PortCount    `json:"top_ports"`
	TopServices     []ServiceCount `json:"top_services"`
	LatestDiscovery time.Time      `json:"latest_discovery"`
}

// PortCount 端口统计
type PortCount struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}

// ServiceCount 服务统计
type ServiceCount struct {
	Service string `json:"service"`
	Count   int    `json:"count"`
}
