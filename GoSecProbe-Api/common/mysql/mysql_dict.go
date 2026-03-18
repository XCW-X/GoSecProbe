package mysql

import (
	"database/sql"
)

// Dict 字典结构体
type Dict struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`      // preset 或 custom
	Category  string `json:"category"`  // 密码、路径、子域名等
	Size      int64  `json:"size"`      // 字节数
	LinesCnt  int64  `json:"lines_cnt"` // 行数
	Path      string `json:"path"`
	CreatedAt string `json:"created_at"`
}

// GetAllDicts 获取所有字典
func GetAllDicts() ([]Dict, error) {
	query := "SELECT id, name, type, category, size, lines_cnt, path, created_at FROM dict ORDER BY type DESC, id ASC"
	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dicts []Dict
	for rows.Next() {
		var d Dict
		var created sql.NullString
		err := rows.Scan(&d.ID, &d.Name, &d.Type, &d.Category, &d.Size, &d.LinesCnt, &d.Path, &created)
		if err != nil {
			continue
		}
		d.CreatedAt = created.String
		dicts = append(dicts, d)
	}
	return dicts, nil
}

// GetDictById 根据ID获取字典
func GetDictById(id int) (Dict, error) {
	var d Dict
	var created sql.NullString
	query := "SELECT id, name, type, category, size, lines_cnt, path, created_at FROM dict WHERE id = ?"
	err := DB.QueryRow(query, id).Scan(&d.ID, &d.Name, &d.Type, &d.Category, &d.Size, &d.LinesCnt, &d.Path, &created)
	d.CreatedAt = created.String
	return d, err
}

// GetDictByName 根据名称获取字典
func GetDictByName(name string) (Dict, error) {
	var d Dict
	var created sql.NullString
	query := "SELECT id, name, type, category, size, lines_cnt, path, created_at FROM dict WHERE name = ?"
	err := DB.QueryRow(query, name).Scan(&d.ID, &d.Name, &d.Type, &d.Category, &d.Size, &d.LinesCnt, &d.Path, &created)
	d.CreatedAt = created.String
	return d, err
}

// UpsertDict 插入或更新字典信息
func UpsertDict(d Dict) error {
	query := `
		INSERT INTO dict (name, type, category, size, lines_cnt, path)
		VALUES (?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		size = VALUES(size),
		lines_cnt = VALUES(lines_cnt),
		path = VALUES(path)
	`
	_, err := DB.Exec(query, d.Name, d.Type, d.Category, d.Size, d.LinesCnt, d.Path)
	return err
}

// DeleteDictById 删除字典
func DeleteDictById(id int) error {
	_, err := DB.Exec("DELETE FROM dict WHERE id = ?", id)
	return err
}
