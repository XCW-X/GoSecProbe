package tools

import (
  "GoSecProbe/common/log"
  "GoSecProbe/common/mysql"
  "GoSecProbe/common/redis"
  "GoSecProbe/model"
  "GoSecProbe/util/fofa"
  "GoSecProbe/util/hunter"
  "GoSecProbe/util/quake"
  "context"
  "encoding/json"
  "errors"
  "fmt"
  "net/http"
  "strconv"
  "strings"
  "time"

  "github.com/gin-gonic/gin"
  goredis "github.com/redis/go-redis/v9"
)

// RegisterRoutes registers tools related routes.
func RegisterRoutes(r *gin.RouterGroup) {
  r.GET("/tools/search-engine", SearchEngine)
  r.GET("/tools/search-engine/cache", GetSearchEngineCache)
  r.GET("/tools/configs", GetToolConfigs)
  r.POST("/tools/configs", UpdateToolConfigs)
}

// SearchEngine handles search engine queries.
func SearchEngine(c *gin.Context) {
  engine := strings.ToLower(strings.TrimSpace(c.Query("engine")))
  query := strings.TrimSpace(c.Query("query"))
  if query == "" {
    c.JSON(http.StatusBadRequest, gin.H{
      "code": 40000,
      "msg":  "查询语句不能为空",
      "data": nil,
    })
    return
  }

  size := 10
  if sizeStr := c.DefaultQuery("size", "10"); sizeStr != "" {
    if v, err := strconv.Atoi(sizeStr); err == nil {
      size = v
    }
  }
  isWeb := parseBool(c.DefaultQuery("is_web", "false"))
  minSize := getEngineMinSize(engine)
  if minSize > 0 && size < minSize {
    c.JSON(http.StatusBadRequest, gin.H{
      "code": 40000,
      "msg":  fmt.Sprintf("页大小不合法，最小搜索条数为 %d", minSize),
      "data": nil,
    })
    return
  }

  apiKey, apiEmail := getToolAPIConfig(engine)
  if apiKey == "" {
    c.JSON(http.StatusBadRequest, gin.H{
      "code": 40000,
      "msg":  "API Key 未配置，请先在“配置API”中设置",
      "data": nil,
    })
    return
  }

  var (
    results []model.SearchResult
    err     error
  )

  switch engine {
  case "hunter":
    results, err = hunter.Search(query, size, isWeb, apiKey)
  case "fofa":
    results, err = fofa.Search(query, size, isWeb, apiKey, apiEmail)
  case "quake":
    results, err = quake.Search(query, size, isWeb, apiKey)
  default:
    c.JSON(http.StatusBadRequest, gin.H{
      "code": 40000,
      "msg":  "不支持的搜索引擎",
      "data": nil,
    })
    return
  }

  if err != nil {
    log.Info("[SearchEngine] %s error: %v", engine, err)
    c.JSON(http.StatusInternalServerError, gin.H{
      "code": 50000,
      "msg":  "搜索失败: " + err.Error(),
      "data": nil,
    })
    return
  }

  if err := saveSearchResults(c, engine, results); err != nil {
    log.Info("[SearchEngine] save results error: %v", err)
    c.JSON(http.StatusInternalServerError, gin.H{
      "code": 50000,
      "msg":  "搜索失败: " + err.Error(),
      "data": nil,
    })
    return
  }

  c.JSON(http.StatusOK, gin.H{
    "code": 20000,
    "msg":  "Success",
    "data": results,
  })
}

func parseBool(value string) bool {
  value = strings.ToLower(strings.TrimSpace(value))
  return value == "1" || value == "true" || value == "yes" || value == "y"
}

func getEngineMinSize(engine string) int {
  switch engine {
  case "hunter":
    return 10
  case "fofa":
    return 1
  case "quake":
    return 1
  default:
    return 0
  }
}

func getToolAPIConfig(engine string) (string, string) {
  apiKey := ""
  apiEmail := ""
  cfg, err := mysql.GetToolConfig(engine)
  if err == nil && cfg != nil {
    apiKey = strings.TrimSpace(cfg.APIKey)
    apiEmail = strings.TrimSpace(cfg.APIEmail)
  }
  return apiKey, apiEmail
}

func saveSearchResults(c *gin.Context, engine string, results []model.SearchResult) error {
  if redis.RedisClient == nil {
    return fmt.Errorf("redis client is not initialized")
  }

  username := ""
  if value, ok := c.Get("username"); ok {
    if v, ok := value.(string); ok {
      username = v
    }
  }
  if username == "" {
    username = "unknown"
  }

  data, err := json.Marshal(results)
  if err != nil {
    return err
  }

  ctx := context.Background()
  key := fmt.Sprintf("search:results:%s:%s", username, engine)
  expiration := 24 * time.Hour
  ttl, err := redis.RedisClient.TTL(ctx, fmt.Sprintf("auth:token:%s", username)).Result()
  if err == nil && ttl > 0 {
    expiration = ttl
  }

  return redis.RedisClient.Set(ctx, key, data, expiration).Err()
}

// GetSearchEngineCache returns cached search results from Redis.
func GetSearchEngineCache(c *gin.Context) {
  engine := strings.ToLower(strings.TrimSpace(c.Query("engine")))
  if engine == "" {
    c.JSON(http.StatusBadRequest, gin.H{
      "code": 40000,
      "msg":  "搜索引擎不能为空",
      "data": nil,
    })
    return
  }

  if redis.RedisClient == nil {
    c.JSON(http.StatusInternalServerError, gin.H{
      "code": 50000,
      "msg":  "Redis 未初始化",
      "data": nil,
    })
    return
  }

  username := ""
  if value, ok := c.Get("username"); ok {
    if v, ok := value.(string); ok {
      username = v
    }
  }
  if username == "" {
    username = "unknown"
  }

  ctx := context.Background()
  key := fmt.Sprintf("search:results:%s:%s", username, engine)
  data, err := redis.RedisClient.Get(ctx, key).Result()
  if err != nil {
    if errors.Is(err, goredis.Nil) {
      c.JSON(http.StatusOK, gin.H{
        "code": 20000,
        "msg":  "Success",
        "data": []model.SearchResult{},
      })
      return
    }
    c.JSON(http.StatusInternalServerError, gin.H{
      "code": 50000,
      "msg":  "读取缓存失败: " + err.Error(),
      "data": nil,
    })
    return
  }

  var results []model.SearchResult
  if err := json.Unmarshal([]byte(data), &results); err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{
      "code": 50000,
      "msg":  "解析缓存失败: " + err.Error(),
      "data": nil,
    })
    return
  }

  c.JSON(http.StatusOK, gin.H{
    "code": 20000,
    "msg":  "Success",
    "data": results,
  })
}
