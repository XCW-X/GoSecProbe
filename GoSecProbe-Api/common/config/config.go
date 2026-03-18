package config

import (
	"os"
	"strconv"
)

// MySQL 配置
var MySQLUser = getEnv("MYSQL_USER", "root")
var MySQLPassword = getEnv("MYSQL_PASSWORD", "GoSecProbe") // 请修改为你的密码
var MySQLHost = getEnv("MYSQL_HOST", "127.0.0.1")
var MySQLPort = getEnvInt("MYSQL_PORT", 3306)
var MySQLDBName = getEnv("MYSQL_DB", "GoSecProbe")

// Redis 配置
var RedisPassword = getEnv("REDIS_PASSWORD", "")
var RedisHost = getEnv("REDIS_HOST", "127.0.0.1")
var RedisPort = getEnvInt("REDIS_PORT", 6379)

// Redis Addr in format host:port for easier docker environment mapping
var RedisAddr = getEnv("REDIS_ADDR", "")

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if value, exists := os.LookupEnv(key); exists {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return fallback
}
