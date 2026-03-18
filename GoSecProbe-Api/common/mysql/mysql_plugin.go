package mysql

import (
	"database/sql"
	"fmt"
)

type Plugin struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	Path        string `json:"path"`
	Config      string `json:"config"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// GetAllPlugins 获取所有插件
func GetAllPlugins() ([]Plugin, error) {
	query := "SELECT id, name, version, type, enabled, description, path, config, created_at, updated_at FROM plugins"
	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var plugins []Plugin
	for rows.Next() {
		var p Plugin
		var config, created, updated sql.NullString
		err := rows.Scan(&p.ID, &p.Name, &p.Version, &p.Type, &p.Enabled, &p.Description, &p.Path, &config, &created, &updated)
		if err != nil {
			continue
		}
		p.Config = config.String
		p.CreatedAt = created.String
		p.UpdatedAt = updated.String
		plugins = append(plugins, p)
	}

	return plugins, nil
}

// UpsertPlugin 添加或更新插件信息
func UpsertPlugin(p Plugin) error {
	query := `
		INSERT INTO plugins (name, version, type, enabled, description, path)
		VALUES (?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		version = VALUES(version),
		type = VALUES(type),
		description = VALUES(description),
		path = VALUES(path)
	`
	_, err := DB.Exec(query, p.Name, p.Version, p.Type, p.Enabled, p.Description, p.Path)
	return err
}

// UpdatePluginStatus 更新插件状态
func UpdatePluginStatus(id int, enabled bool) error {
	query := "UPDATE plugins SET enabled = ? WHERE id = ?"
	res, err := DB.Exec(query, enabled, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("plugin not found or status not changed")
	}
	return nil
}

// UpdatePluginConfig 更新插件配置
func UpdatePluginConfig(id int, config string) error {
	query := "UPDATE plugins SET config = ? WHERE id = ?"
	res, err := DB.Exec(query, config, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("plugin not found")
	}
	return nil
}

// IsPluginEnabled 检查插件是否启用
func IsPluginEnabled(name string) bool {
	var enabled bool
	err := DB.QueryRow("SELECT enabled FROM plugins WHERE name = ?", name).Scan(&enabled)
	if err != nil {
		return false
	}
	return enabled
}

// GetPluginConfig 获取插件配置
func GetPluginConfig(name string) string {
	var config sql.NullString
	err := DB.QueryRow("SELECT config FROM plugins WHERE name = ?", name).Scan(&config)
	if err != nil {
		return ""
	}
	return config.String
}
