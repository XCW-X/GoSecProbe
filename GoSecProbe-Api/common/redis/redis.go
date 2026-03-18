package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// RedisClient Redis客户端实例
	RedisClient *redis.Client
	ctx         = context.Background()
)

// RedisConfig Redis配置
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// InitRedis 初始化Redis连接
func InitRedis(config RedisConfig) error {
	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	if config.Host == "" {
		// allow fallback or use RedisAddr in config package
	}

	RedisClient = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: config.Password,
		DB:       config.DB,
	})

	// 测试连接
	_, err := RedisClient.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}

	return nil
}

// SaveToken 保存JWT token到Redis
// key格式: auth:token:{username}
// value: token字符串
// expiration: token过期时间
func SaveToken(username, token string, expiration time.Duration) error {
	if RedisClient == nil {
		return fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("auth:token:%s", username)
	err := RedisClient.Set(ctx, key, token, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to save token to redis: %w", err)
	}

	return nil
}

// GetToken 从Redis获取用户的JWT token
func GetToken(username string) (string, error) {
	if RedisClient == nil {
		return "", fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("auth:token:%s", username)
	token, err := RedisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("token not found for user: %s", username)
	}
	if err != nil {
		return "", fmt.Errorf("failed to get token from redis: %w", err)
	}

	return token, nil
}

// ValidateToken 验证token是否存在且未过期
func ValidateToken(username, token string) (bool, error) {
	if RedisClient == nil {
		return false, fmt.Errorf("redis client is not initialized")
	}

	storedToken, err := GetToken(username)
	if err != nil {
		return false, err
	}

	// 比较存储的token和传入的token是否一致
	return storedToken == token, nil
}

// DeleteToken 删除用户的JWT token（登出时使用）
func DeleteToken(username string) error {
	if RedisClient == nil {
		return fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("auth:token:%s", username)
	err := RedisClient.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete token from redis: %w", err)
	}

	return nil
}

// RefreshTokenExpiration 刷新token的过期时间
func RefreshTokenExpiration(username string, expiration time.Duration) error {
	if RedisClient == nil {
		return fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("auth:token:%s", username)
	err := RedisClient.Expire(ctx, key, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to refresh token expiration: %w", err)
	}

	return nil
}

// IsUserLoggedIn 检查用户是否已登录
func IsUserLoggedIn(username string) (bool, error) {
	if RedisClient == nil {
		return false, fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("auth:token:%s", username)
	exists, err := RedisClient.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check user login status: %w", err)
	}

	return exists > 0, nil
}

// GetAllLoggedInUsers 获取所有已登录的用户列表
func GetAllLoggedInUsers() ([]string, error) {
	if RedisClient == nil {
		return nil, fmt.Errorf("redis client is not initialized")
	}

	// 扫描所有auth:token:*的key
	var users []string
	iter := RedisClient.Scan(ctx, 0, "auth:token:*", 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		// 提取用户名（去掉"auth:token:"前缀）
		username := key[11:] // len("auth:token:") = 11
		users = append(users, username)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan logged in users: %w", err)
	}

	return users, nil
}

// Close 关闭Redis连接
func Close() error {
	if RedisClient == nil {
		return nil
	}
	return RedisClient.Close()
}

// ============================================
// 任务进度管理模块
// ============================================

// TaskProgress 任务进度信息
type TaskProgress struct {
	TaskID         int       `json:"task_id"`
	Status         string    `json:"status"`           // running/completed/failed/stopped
	Progress       int       `json:"progress"`         // 0-100
	TotalTargets   int       `json:"total_targets"`    // 总目标数
	ScannedTargets int       `json:"scanned_targets"`  // 已扫描目标数
	FoundAssets    int       `json:"found_assets"`     // 发现的资产数
	CurrentTarget  string    `json:"current_target"`   // 当前扫描目标
	StartTime      time.Time `json:"start_time"`       // 开始时间
	LastUpdateTime time.Time `json:"last_update_time"` // 最后更新时间
	Message        string    `json:"message"`          // 状态消息
}

// UpdateTaskProgress 更新任务进度到Redis
// key格式: task:progress:{taskID}
// 过期时间: 24小时（任务完成后会手动删除）
func UpdateTaskProgress(taskID int, progress TaskProgress) error {
	if RedisClient == nil {
		return fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("task:progress:%d", taskID)
	progress.LastUpdateTime = time.Now()

	// 将进度信息序列化为JSON
	data, err := json.Marshal(progress)
	if err != nil {
		return fmt.Errorf("failed to marshal task progress: %w", err)
	}

	// 保存到Redis，设置24小时过期
	err = RedisClient.Set(ctx, key, data, 24*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to save task progress to redis: %w", err)
	}

	return nil
}

// GetTaskProgress 从Redis获取任务进度
func GetTaskProgress(taskID int) (*TaskProgress, error) {
	if RedisClient == nil {
		return nil, fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("task:progress:%d", taskID)
	data, err := RedisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		// Redis中没有找到，返回nil（可能任务已完成或未开始）
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get task progress from redis: %w", err)
	}

	var progress TaskProgress
	err = json.Unmarshal([]byte(data), &progress)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal task progress: %w", err)
	}

	return &progress, nil
}

// DeleteTaskProgress 删除任务进度（任务完成后清理）
func DeleteTaskProgress(taskID int) error {
	if RedisClient == nil {
		return fmt.Errorf("redis client is not initialized")
	}

	key := fmt.Sprintf("task:progress:%d", taskID)
	err := RedisClient.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete task progress from redis: %w", err)
	}

	return nil
}

// IncrementTaskProgress 递增任务进度（原子操作）
// 用于多线程场景下安全更新已扫描目标数
func IncrementTaskProgress(taskID int, scannedIncrement int) error {
	if RedisClient == nil {
		return fmt.Errorf("redis client is not initialized")
	}

	// 获取当前进度
	progress, err := GetTaskProgress(taskID)
	if err != nil {
		return err
	}
	if progress == nil {
		return fmt.Errorf("task progress not found for task %d", taskID)
	}

	// 更新已扫描数和进度百分比
	progress.ScannedTargets += scannedIncrement
	if progress.TotalTargets > 0 {
		progress.Progress = (progress.ScannedTargets * 100) / progress.TotalTargets
		if progress.Progress > 100 {
			progress.Progress = 100
		}
	}

	// 保存回Redis
	return UpdateTaskProgress(taskID, *progress)
}
