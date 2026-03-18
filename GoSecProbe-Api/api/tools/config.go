package tools

import (
	"GoSecProbe/common/mysql"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ToolConfigUpdateRequest 更新工具配置请求
type ToolConfigUpdateRequest struct {
	HunterKey string `json:"hunter_key"`
	FofaKey   string `json:"fofa_key"`
	FofaEmail string `json:"fofa_email"`
	QuakeKey  string `json:"quake_key"`
}

// GetToolConfigs 获取工具配置
func GetToolConfigs(c *gin.Context) {
	configs, err := mysql.GetAllToolConfigs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "获取工具配置失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	result := make(map[string]map[string]string)
	for _, cfg := range configs {
		result[cfg.Name] = map[string]string{
			"api_key":   cfg.APIKey,
			"api_email": cfg.APIEmail,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "Success",
		"data": result,
	})
}

// UpdateToolConfigs 更新工具配置
func UpdateToolConfigs(c *gin.Context) {
	var req ToolConfigUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code": 40000,
			"msg":  "请求参数错误: " + err.Error(),
			"data": nil,
		})
		return
	}

	if err := mysql.UpsertToolConfig("hunter", req.HunterKey, ""); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "保存 Hunter 配置失败: " + err.Error(),
			"data": nil,
		})
		return
	}
	if err := mysql.UpsertToolConfig("fofa", req.FofaKey, req.FofaEmail); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "保存 FOFA 配置失败: " + err.Error(),
			"data": nil,
		})
		return
	}
	if err := mysql.UpsertToolConfig("quake", req.QuakeKey, ""); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": 50000,
			"msg":  "保存 Quake 配置失败: " + err.Error(),
			"data": nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "保存成功",
		"data": nil,
	})
}
