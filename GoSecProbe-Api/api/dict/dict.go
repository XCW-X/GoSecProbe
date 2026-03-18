package dict

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup) {
	r.GET("/dict/list", GetDicts)
	r.POST("/dict/sync", SyncDicts)
	r.GET("/dict/view", ViewDict)
	r.GET("/dict/download", DownloadDict)
	r.POST("/dict/upload", UploadDict)
	r.DELETE("/dict/delete/:id", DeleteDict)
	// 字典生成
	r.POST("/dict/generate/social", GenerateSocialDict)
	r.POST("/dict/generate/combo", GenerateComboDict)
}

func countLines(filepath string) int64 {
	file, err := os.Open(filepath)
	if err != nil {
		return 0
	}
	defer file.Close()

	buf := make([]byte, 32*1024)
	var count int64 = 0
	lineSep := []byte{'\n'}
	for {
		c, err := file.Read(buf)
		count += int64(bytes.Count(buf[:c], lineSep))
		if err == io.EOF {
			return count
		}
		if err != nil {
			return count
		}
	}
}

func scanAndSyncDir(dirPath string, dictType string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		os.MkdirAll(dirPath, 0755)
		return nil
	}

	return filepath.WalkDir(dirPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			return nil
		}

		// Guess category
		lowerPath := strings.ToLower(filepath.ToSlash(path))
		category := "其他字典"
		if strings.Contains(lowerPath, "pass") || strings.Contains(lowerPath, "pwd") {
			category = "密码字典"
		} else if strings.Contains(lowerPath, "domain") || strings.Contains(lowerPath, "dns") || strings.Contains(lowerPath, "sub") {
			category = "子域名字典"
		} else if strings.Contains(lowerPath, "dir") || strings.Contains(lowerPath, "path") || strings.Contains(lowerPath, "web") || strings.Contains(lowerPath, "fuzz") {
			category = "路径字典"
		}

		info, err := entry.Info()
		if err != nil {
			return nil
		}
		size := info.Size()

		// Check DB to avoid recompiling lines if size is same
		var linesCnt int64 = 0
		existing, err := mysql.GetDictByName(name)
		if err == nil && existing.Size == size {
			linesCnt = existing.LinesCnt
		} else {
			linesCnt = countLines(path)
		}

		d := mysql.Dict{
			Name:     name,
			Type:     dictType,
			Category: category,
			Size:     size,
			LinesCnt: linesCnt,
			Path:     path,
		}
		err = mysql.UpsertDict(d)
		if err != nil {
			log.Warn("Upsert dict error: %v", err)
		}
		return nil
	})
}

func syncAllDicts() error {
	err := scanAndSyncDir("./service/dict", "preset")
	if err != nil {
		return err
	}
	return scanAndSyncDir("./uploads/dict", "custom")
}

func SyncDicts(c *gin.Context) {
	err := syncAllDicts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 50000, "msg": "Sync Failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 20000, "msg": "success"})
}

func GetDicts(c *gin.Context) {
	// Sync slightly before query for fresh data (may delay response slightly, ideally frontend triggers sync)
	_ = syncAllDicts()

	typeParam := c.Query("type")
	categoryParam := c.Query("category")

	dicts, err := mysql.GetAllDicts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 50000, "msg": err.Error(), "data": nil})
		return
	}

	var result []mysql.Dict
	for _, d := range dicts {
		if typeParam != "" && d.Type != typeParam {
			continue
		}
		if categoryParam != "" && d.Category != categoryParam {
			continue
		}
		result = append(result, d)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "success",
		"data": result,
	})
}

// ViewDict 获取前100行内容
func ViewDict(c *gin.Context) {
	idStr := c.Query("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "id invalid"})
		return
	}

	d, err := mysql.GetDictById(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 40400, "msg": "dict not found"})
		return
	}

	file, err := os.Open(d.Path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 50000, "msg": err.Error()})
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		count++
		if count >= 100 {
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "success",
		"data": strings.Join(lines, "\n"),
	})
}

// DownloadDict 下载字典文件
func DownloadDict(c *gin.Context) {
	idStr := c.Query("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "id invalid"})
		return
	}

	d, err := mysql.GetDictById(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": 40400, "msg": "dict not found"})
		return
	}

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, d.Name))
	c.Header("Content-Type", "application/octet-stream")
	c.File(d.Path)
}

// UploadDict 导入字典文件
func UploadDict(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "Upload failed"})
		return
	}

	uploadDir := "./uploads/dict"
	os.MkdirAll(uploadDir, 0755)

	// Save file safely avoiding collisions
	ts := time.Now().Unix()
	filename := fmt.Sprintf("%d_%s", ts, file.Filename)
	path := filepath.Join(uploadDir, filename)

	if err := c.SaveUploadedFile(file, path); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 50000, "msg": "Save file failure: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "Import success",
	})
}

func DeleteDict(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "id invalid"})
		return
	}

	d, err := mysql.GetDictById(id)
	if err == nil {
		os.Remove(d.Path)
	}

	mysql.DeleteDictById(id)
	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "Delete success",
	})
}
