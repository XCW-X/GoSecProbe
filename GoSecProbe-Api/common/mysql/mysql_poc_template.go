package mysql

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PocTemplate POC模板结构体
type PocTemplate struct {
	ID              int64      `json:"id"`
	TemplateID      string     `json:"template_id"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	Author          string     `json:"author"`
	Category        string     `json:"category"`
	Severity        string     `json:"severity"`
	Tags            string     `json:"tags"` // JSON数组
	CveID           string     `json:"cve_id"`
	CnvdID          string     `json:"cnvd_id"` // 新增CNVD
	CweID           string     `json:"cwe_id"`
	CvssScore       float32    `json:"cvss_score"`
	CvssMetrics     string     `json:"cvss_metrics"`
	Protocol        string     `json:"protocol"`
	MaxRequest      int        `json:"max_request"`
	Reference       string     `json:"reference"`      // JSON数组
	Classification  string     `json:"classification"` // JSON对象
	Metadata        string     `json:"metadata"`       // JSON对象
	FilePath        string     `json:"file_path"`
	FileHash        string     `json:"file_hash"`
	TemplateContent string     `json:"template_content"`
	IsActive        bool       `json:"is_active"`
	Verified        bool       `json:"verified"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastScannedAt   *time.Time `json:"last_scanned_at"`
}

// ErrDuplicatePoc 表示POC模板已存在的错误
var ErrDuplicatePoc = errors.New("duplicate_poc")

// SavePocTemplate 保存POC模板（带哈希去重）
func SavePocTemplate(poc *PocTemplate) error {
	// 检查文件哈希是否已存在
	if poc.FileHash != "" {
		var existingID int64
		err := DB.QueryRow("SELECT id FROM poc_template WHERE file_hash = ?", poc.FileHash).Scan(&existingID)
		if err == nil {
			// 哈希已存在，返回重复错误
			return fmt.Errorf("%w: 此POC模板已存在（ID: %d），无需重复导入", ErrDuplicatePoc, existingID)
		}
		// 如果是其他错误（非 no rows），返回错误
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	// 检查 template_id 是否已存在
	var existingID int64
	err := DB.QueryRow("SELECT id FROM poc_template WHERE template_id = ?", poc.TemplateID).Scan(&existingID)
	if err == nil {
		// template_id 已存在，返回重复错误
		return fmt.Errorf("%w: 相同模板ID '%s' 已存在（ID: %d），无需重复导入", ErrDuplicatePoc, poc.TemplateID, existingID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	query := `INSERT INTO poc_template (
		template_id, name, description, author, category, severity, tags,
		cve_id, cnvd_id, cwe_id, cvss_score, cvss_metrics, protocol, max_request,
		reference, classification, metadata, file_path, file_hash,
		template_content, is_active, verified
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := DB.Exec(query,
		poc.TemplateID, poc.Name, poc.Description, poc.Author, poc.Category,
		poc.Severity, poc.Tags, poc.CveID, poc.CnvdID, poc.CweID, poc.CvssScore,
		poc.CvssMetrics, poc.Protocol, poc.MaxRequest, poc.Reference,
		poc.Classification, poc.Metadata, poc.FilePath, poc.FileHash,
		poc.TemplateContent, poc.IsActive, poc.Verified,
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err == nil {
		poc.ID = id
	}
	return nil
}

// BatchSavePocTemplates 批量保存POC模板（去重）
// 返回实际保存的POC数量和可能的错误
func BatchSavePocTemplates(pocs []*PocTemplate) (int, error) {
	if len(pocs) == 0 {
		return 0, nil
	}

	// 1. 收集所有文件哈希
	hashes := make([]string, 0, len(pocs))
	hashToPoc := make(map[string]*PocTemplate)
	for _, poc := range pocs {
		if poc.FileHash != "" {
			hashes = append(hashes, poc.FileHash)
			hashToPoc[poc.FileHash] = poc
		}
	}

	// 2. 查询数据库中已存在的哈希
	existingHashes := make(map[string]bool)
	if len(hashes) > 0 {
		placeholders := make([]string, len(hashes))
		args := make([]interface{}, len(hashes))
		for i, hash := range hashes {
			placeholders[i] = "?"
			args[i] = hash
		}

		query := "SELECT file_hash FROM poc_template WHERE file_hash IN (" +
			strings.Join(placeholders, ",") + ")"

		rows, err := DB.Query(query, args...)
		if err != nil {
			return 0, err
		}
		defer rows.Close()

		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				return 0, err
			}
			existingHashes[hash] = true
		}
	}

	// 3. 过滤出需要新增的POC（哈希不存在的）
	newPocs := make([]*PocTemplate, 0)
	for _, poc := range pocs {
		if poc.FileHash == "" || !existingHashes[poc.FileHash] {
			newPocs = append(newPocs, poc)
		}
	}

	// 如果没有新的POC需要保存，直接返回
	if len(newPocs) == 0 {
		return 0, nil
	}

	// 4. 批量插入新的POC
	tx, err := DB.Begin()
	if err != nil {
		return 0, err
	}

	query := `INSERT INTO poc_template (
		template_id, name, description, author, category, severity, tags,
		cve_id, cnvd_id, cwe_id, cvss_score, cvss_metrics, protocol, max_request,
		reference, classification, metadata, file_path, file_hash,
		template_content, is_active, verified
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON DUPLICATE KEY UPDATE
		name = VALUES(name), description = VALUES(description), author = VALUES(author),
		category = VALUES(category), severity = VALUES(severity), tags = VALUES(tags),
		cve_id = VALUES(cve_id), cnvd_id = VALUES(cnvd_id), cwe_id = VALUES(cwe_id),
		cvss_score = VALUES(cvss_score), cvss_metrics = VALUES(cvss_metrics),
		protocol = VALUES(protocol), max_request = VALUES(max_request),
		reference = VALUES(reference), classification = VALUES(classification),
		metadata = VALUES(metadata), file_path = VALUES(file_path),
		file_hash = VALUES(file_hash), template_content = VALUES(template_content),
		updated_at = NOW()`

	stmt, err := tx.Prepare(query)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	defer stmt.Close()

	for _, poc := range newPocs {
		_, err := stmt.Exec(
			poc.TemplateID, poc.Name, poc.Description, poc.Author, poc.Category,
			poc.Severity, poc.Tags, poc.CveID, poc.CnvdID, poc.CweID, poc.CvssScore,
			poc.CvssMetrics, poc.Protocol, poc.MaxRequest, poc.Reference,
			poc.Classification, poc.Metadata, poc.FilePath, poc.FileHash,
			poc.TemplateContent, poc.IsActive, poc.Verified,
		)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return len(newPocs), nil
}

// UpdatePocTemplate 更新POC模板
func UpdatePocTemplate(poc *PocTemplate) error {
	query := `UPDATE poc_template SET
		name = ?, description = ?, author = ?, category = ?, severity = ?,
		tags = ?, cve_id = ?, cnvd_id = ?, cwe_id = ?, cvss_score = ?, cvss_metrics = ?,
		protocol = ?, max_request = ?, reference = ?, classification = ?,
		metadata = ?, file_path = ?, file_hash = ?, template_content = ?,
		is_active = ?, verified = ?, updated_at = NOW()
	WHERE id = ?`

	_, err := DB.Exec(query,
		poc.Name, poc.Description, poc.Author, poc.Category, poc.Severity,
		poc.Tags, poc.CveID, poc.CnvdID, poc.CweID, poc.CvssScore, poc.CvssMetrics,
		poc.Protocol, poc.MaxRequest, poc.Reference, poc.Classification,
		poc.Metadata, poc.FilePath, poc.FileHash, poc.TemplateContent,
		poc.IsActive, poc.Verified, poc.ID,
	)
	return err
}

// GetPocTemplateByID 根据ID获取POC模板
func GetPocTemplateByID(id int64) (*PocTemplate, error) {
	poc := &PocTemplate{}
	query := `SELECT id, template_id, name, 
		COALESCE(description, ''), COALESCE(author, ''), COALESCE(category, ''), COALESCE(severity, ''),
		COALESCE(tags, ''), COALESCE(cve_id, ''), COALESCE(cnvd_id, ''), COALESCE(cwe_id, ''), 
		COALESCE(cvss_score, 0), COALESCE(cvss_metrics, ''), COALESCE(protocol, ''), COALESCE(max_request, 1),
		COALESCE(reference, ''), COALESCE(classification, ''), COALESCE(metadata, ''), 
		file_path, COALESCE(file_hash, ''), COALESCE(template_content, ''),
		is_active, verified, created_at, updated_at, last_scanned_at
	FROM poc_template WHERE id = ?`

	err := DB.QueryRow(query, id).Scan(
		&poc.ID, &poc.TemplateID, &poc.Name, &poc.Description, &poc.Author,
		&poc.Category, &poc.Severity, &poc.Tags, &poc.CveID, &poc.CnvdID, &poc.CweID,
		&poc.CvssScore, &poc.CvssMetrics, &poc.Protocol, &poc.MaxRequest,
		&poc.Reference, &poc.Classification, &poc.Metadata, &poc.FilePath,
		&poc.FileHash, &poc.TemplateContent, &poc.IsActive, &poc.Verified,
		&poc.CreatedAt, &poc.UpdatedAt, &poc.LastScannedAt,
	)
	if err != nil {
		return nil, err
	}
	return poc, nil
}

// GetPocTemplateByTemplateID 根据模板ID获取POC模板
func GetPocTemplateByTemplateID(templateID string) (*PocTemplate, error) {
	poc := &PocTemplate{}
	query := `SELECT id, template_id, name, 
		COALESCE(description, ''), COALESCE(author, ''), COALESCE(category, ''), COALESCE(severity, ''),
		COALESCE(tags, ''), COALESCE(cve_id, ''), COALESCE(cnvd_id, ''), COALESCE(cwe_id, ''), 
		COALESCE(cvss_score, 0), COALESCE(cvss_metrics, ''), COALESCE(protocol, ''), COALESCE(max_request, 1),
		COALESCE(reference, ''), COALESCE(classification, ''), COALESCE(metadata, ''), 
		file_path, COALESCE(file_hash, ''), COALESCE(template_content, ''),
		is_active, verified, created_at, updated_at, last_scanned_at
	FROM poc_template WHERE template_id = ?`

	err := DB.QueryRow(query, templateID).Scan(
		&poc.ID, &poc.TemplateID, &poc.Name, &poc.Description, &poc.Author,
		&poc.Category, &poc.Severity, &poc.Tags, &poc.CveID, &poc.CnvdID, &poc.CweID,
		&poc.CvssScore, &poc.CvssMetrics, &poc.Protocol, &poc.MaxRequest,
		&poc.Reference, &poc.Classification, &poc.Metadata, &poc.FilePath,
		&poc.FileHash, &poc.TemplateContent, &poc.IsActive, &poc.Verified,
		&poc.CreatedAt, &poc.UpdatedAt, &poc.LastScannedAt,
	)
	if err != nil {
		return nil, err
	}
	return poc, nil
}

func GetActivePocTemplates() ([]*PocTemplate, error) {
	query := `SELECT id, template_id, name, 
		COALESCE(description, ''), COALESCE(author, ''), COALESCE(category, ''), COALESCE(severity, ''),
		COALESCE(tags, ''), COALESCE(cve_id, ''), COALESCE(cnvd_id, ''), COALESCE(cwe_id, ''), 
		COALESCE(cvss_score, 0), COALESCE(cvss_metrics, ''), COALESCE(protocol, ''), COALESCE(max_request, 1),
		COALESCE(reference, ''), COALESCE(classification, ''), COALESCE(metadata, ''), 
		file_path, COALESCE(file_hash, ''), COALESCE(template_content, ''),
		is_active, verified, created_at, updated_at, last_scanned_at
	FROM poc_template WHERE is_active = 1`

	rows, err := DB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	pocs := make([]*PocTemplate, 0)
	for rows.Next() {
		poc := &PocTemplate{}
		err := rows.Scan(
			&poc.ID, &poc.TemplateID, &poc.Name, &poc.Description, &poc.Author,
			&poc.Category, &poc.Severity, &poc.Tags, &poc.CveID, &poc.CnvdID, &poc.CweID,
			&poc.CvssScore, &poc.CvssMetrics, &poc.Protocol, &poc.MaxRequest,
			&poc.Reference, &poc.Classification, &poc.Metadata, &poc.FilePath,
			&poc.FileHash, &poc.TemplateContent, &poc.IsActive, &poc.Verified,
			&poc.CreatedAt, &poc.UpdatedAt, &poc.LastScannedAt,
		)
		if err != nil {
			return nil, err
		}
		pocs = append(pocs, poc)
	}
	return pocs, nil
}

// ListPocTemplates 获取POC模板列表
func ListPocTemplates(page, pageSize int, filters map[string]interface{}, sort, order string) ([]PocTemplate, int64, error) {
	whereClause := "WHERE 1=1"
	var args []interface{}

	if name, ok := filters["name"].(string); ok && name != "" {
		whereClause += " AND name LIKE ?"
		args = append(args, "%"+name+"%")
	}
	if category, ok := filters["category"].(string); ok && category != "" {
		whereClause += " AND category = ?"
		args = append(args, category)
	}
	if severity, ok := filters["severity"].(string); ok && severity != "" {
		whereClause += " AND severity = ?"
		args = append(args, severity)
	}
	// 改为模糊匹配
	if cveID, ok := filters["cve_id"].(string); ok && cveID != "" {
		whereClause += " AND cve_id LIKE ?"
		args = append(args, "%"+cveID+"%")
	}
	// 添加 CNVD 模糊匹配
	if cnvdID, ok := filters["cnvd_id"].(string); ok && cnvdID != "" {
		whereClause += " AND cnvd_id LIKE ?"
		args = append(args, "%"+cnvdID+"%")
	}
	if protocol, ok := filters["protocol"].(string); ok && protocol != "" {
		whereClause += " AND protocol = ?"
		args = append(args, protocol)
	}
	if isActive, ok := filters["is_active"].(bool); ok {
		whereClause += " AND is_active = ?"
		args = append(args, isActive)
	}

	countQuery := "SELECT COUNT(*) FROM poc_template " + whereClause
	var total int64
	err := DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// 排序逻辑校验，防止SQL注入
	sortField := "id"
	if sort == "created_at" {
		sortField = "created_at"
	}
	sortOrder := "DESC"
	if strings.ToUpper(order) == "ASC" {
		sortOrder = "ASC"
	}

	offset := (page - 1) * pageSize
	query := `SELECT id, template_id, name, 
		COALESCE(description, ''), COALESCE(author, ''), COALESCE(category, ''), COALESCE(severity, ''),
		COALESCE(tags, ''), COALESCE(cve_id, ''), COALESCE(cnvd_id, ''), COALESCE(cwe_id, ''), 
		COALESCE(cvss_score, 0), COALESCE(cvss_metrics, ''), COALESCE(protocol, ''), COALESCE(max_request, 1),
		COALESCE(reference, ''), COALESCE(classification, ''), COALESCE(metadata, ''), 
		file_path, COALESCE(file_hash, ''), COALESCE(template_content, ''),
		is_active, verified, created_at, updated_at, last_scanned_at
	FROM poc_template ` + whereClause + ` ORDER BY ` + sortField + ` ` + sortOrder + ` LIMIT ? OFFSET ?`

	args = append(args, pageSize, offset)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pocs []PocTemplate
	for rows.Next() {
		var poc PocTemplate
		err := rows.Scan(
			&poc.ID, &poc.TemplateID, &poc.Name, &poc.Description, &poc.Author,
			&poc.Category, &poc.Severity, &poc.Tags, &poc.CveID, &poc.CnvdID, &poc.CweID,
			&poc.CvssScore, &poc.CvssMetrics, &poc.Protocol, &poc.MaxRequest,
			&poc.Reference, &poc.Classification, &poc.Metadata, &poc.FilePath,
			&poc.FileHash, &poc.TemplateContent, &poc.IsActive, &poc.Verified,
			&poc.CreatedAt, &poc.UpdatedAt, &poc.LastScannedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		pocs = append(pocs, poc)
	}
	return pocs, total, nil
}

// SearchPocTemplates 搜索POC模板 (全局搜索)
func SearchPocTemplates(keyword string, page, pageSize int) ([]PocTemplate, int64, error) {
	whereClause := "WHERE name LIKE ? OR description LIKE ? OR template_id LIKE ? OR cve_id LIKE ? OR cnvd_id LIKE ?"
	pattern := "%" + keyword + "%"
	args := []interface{}{pattern, pattern, pattern, pattern, pattern}

	countQuery := "SELECT COUNT(*) FROM poc_template " + whereClause
	var total int64
	err := DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	query := `SELECT id, template_id, name, 
		COALESCE(description, ''), COALESCE(author, ''), COALESCE(category, ''), COALESCE(severity, ''),
		COALESCE(tags, ''), COALESCE(cve_id, ''), COALESCE(cnvd_id, ''), COALESCE(cwe_id, ''), 
		COALESCE(cvss_score, 0), COALESCE(cvss_metrics, ''), COALESCE(protocol, ''), COALESCE(max_request, 1),
		COALESCE(reference, ''), COALESCE(classification, ''), COALESCE(metadata, ''), 
		file_path, COALESCE(file_hash, ''), COALESCE(template_content, ''),
		is_active, verified, created_at, updated_at, last_scanned_at
	FROM poc_template ` + whereClause + ` ORDER BY id DESC LIMIT ? OFFSET ?`

	args = append(args, pageSize, offset)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var pocs []PocTemplate
	for rows.Next() {
		var poc PocTemplate
		err := rows.Scan(
			&poc.ID, &poc.TemplateID, &poc.Name, &poc.Description, &poc.Author,
			&poc.Category, &poc.Severity, &poc.Tags, &poc.CveID, &poc.CnvdID, &poc.CweID,
			&poc.CvssScore, &poc.CvssMetrics, &poc.Protocol, &poc.MaxRequest,
			&poc.Reference, &poc.Classification, &poc.Metadata, &poc.FilePath,
			&poc.FileHash, &poc.TemplateContent, &poc.IsActive, &poc.Verified,
			&poc.CreatedAt, &poc.UpdatedAt, &poc.LastScannedAt,
		)
		if err != nil {
			return nil, 0, err
		}
		pocs = append(pocs, poc)
	}
	return pocs, total, nil
}

// DeletePocTemplate 删除POC模板
func DeletePocTemplate(id int64) error {
	_, err := DB.Exec("DELETE FROM poc_template WHERE id = ?", id)
	return err
}

// BatchDeletePocTemplates 批量删除POC模板
func BatchDeletePocTemplates(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	query := "DELETE FROM poc_template WHERE id IN ("
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		if i > 0 {
			query += ","
		}
		query += "?"
		args[i] = id
	}
	query += ")"

	_, err := DB.Exec(query, args...)
	return err
}

// GetPocTemplateStats 获取POC统计信息
func GetPocTemplateStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	var total int64
	err := DB.QueryRow("SELECT COUNT(*) FROM poc_template").Scan(&total)
	if err != nil {
		return nil, err
	}
	stats["total"] = total

	rows, err := DB.Query("SELECT severity, COUNT(*) FROM poc_template GROUP BY severity")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	severityStats := make(map[string]int64)
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err == nil {
			severityStats[severity] = count
		}
	}
	stats["severity"] = severityStats

	return stats, nil
}

// PocTemplateListResponse 用于前端列表展示的轻量级结构
type PocTemplateListResponse struct {
	ID         int64    `json:"id"`
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Tags       []string `json:"tags"`
	CveID      string   `json:"cve_id"`
	CnvdID     string   `json:"cnvd_id"`
	Protocol   string   `json:"protocol"`
	Author     string   `json:"author"`
	IsActive   bool     `json:"is_active"`
	Verified   bool     `json:"verified"`
	CreatedAt  string   `json:"created_at"`
}

// PocTemplateDetailResponse 用于前端详情展示的完整结构
type PocTemplateDetailResponse struct {
	ID              int64                  `json:"id"`
	TemplateID      string                 `json:"template_id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Author          string                 `json:"author"`
	Category        string                 `json:"category"`
	Severity        string                 `json:"severity"`
	Tags            []string               `json:"tags"`
	CveID           string                 `json:"cve_id"`
	CnvdID          string                 `json:"cnvd_id"`
	CweID           string                 `json:"cwe_id"`
	CvssScore       float32                `json:"cvss_score"`
	CvssMetrics     string                 `json:"cvss_metrics"`
	Protocol        string                 `json:"protocol"`
	MaxRequest      int                    `json:"max_request"`
	Reference       []string               `json:"reference"`
	Classification  map[string]interface{} `json:"classification"`
	Metadata        map[string]interface{} `json:"metadata"`
	FilePath        string                 `json:"file_path"`
	TemplateContent string                 `json:"template_content"`
	IsActive        bool                   `json:"is_active"`
	Verified        bool                   `json:"verified"`
	CreatedAt       string                 `json:"created_at"`
	UpdatedAt       string                 `json:"updated_at"`
}

// ConvertToListResponse 转换为列表响应格式
func (p *PocTemplate) ConvertToListResponse() PocTemplateListResponse {
	var tags []string
	if p.Tags != "" {
		json.Unmarshal([]byte(p.Tags), &tags)
	}

	cveID := p.CveID
	if cveID == "" {
		cveID = "-"
	}

	cnvdID := p.CnvdID
	if cnvdID == "" {
		cnvdID = "-"
	}

	// 将英文severity转换为中文
	severityMap := map[string]string{
		"critical": "严重",
		"high":     "高危",
		"medium":   "中危",
		"low":      "低危",
		"info":     "信息",
	}
	// 数据库中存储的是小写英文，转换为中文展示
	severity := severityMap[strings.ToLower(p.Severity)]
	// 如果转换失败（可能是已经是中文或者未知级别），则保持原样
	if severity == "" {
		severity = p.Severity
	}

	return PocTemplateListResponse{
		ID:         p.ID,
		TemplateID: p.TemplateID,
		Name:       p.Name,
		Category:   p.Category,
		Severity:   severity,
		Tags:       tags,
		CveID:      cveID,
		CnvdID:     cnvdID,
		Protocol:   p.Protocol,
		Author:     p.Author,
		IsActive:   p.IsActive,
		Verified:   p.Verified,
		CreatedAt:  p.CreatedAt.Format("2006-01-02 15:04:05"),
	}
}

// ConvertToDetailResponse 转换为详情响应格式
func (p *PocTemplate) ConvertToDetailResponse() PocTemplateDetailResponse {
	var tags []string
	if p.Tags != "" {
		json.Unmarshal([]byte(p.Tags), &tags)
	}

	var references []string
	if p.Reference != "" {
		json.Unmarshal([]byte(p.Reference), &references)
	}

	var classification map[string]interface{}
	if p.Classification != "" {
		json.Unmarshal([]byte(p.Classification), &classification)
	}

	var metadata map[string]interface{}
	if p.Metadata != "" {
		json.Unmarshal([]byte(p.Metadata), &metadata)
	}

	return PocTemplateDetailResponse{
		ID:              p.ID,
		TemplateID:      p.TemplateID,
		Name:            p.Name,
		Description:     p.Description,
		Author:          p.Author,
		Category:        p.Category,
		Severity:        p.Severity,
		Tags:            tags,
		CveID:           p.CveID,
		CnvdID:          p.CnvdID,
		CweID:           p.CweID,
		CvssScore:       p.CvssScore,
		CvssMetrics:     p.CvssMetrics,
		Protocol:        p.Protocol,
		MaxRequest:      p.MaxRequest,
		Reference:       references,
		Classification:  classification,
		Metadata:        metadata,
		FilePath:        p.FilePath,
		TemplateContent: p.TemplateContent,
		IsActive:        p.IsActive,
		Verified:        p.Verified,
		CreatedAt:       p.CreatedAt.Format("2006-01-02 15:04:05"),
		UpdatedAt:       p.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
}
