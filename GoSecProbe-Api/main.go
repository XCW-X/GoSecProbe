package main

import (
	"GoSecProbe/api"
	"GoSecProbe/common/config"
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"GoSecProbe/common/redis"
	"GoSecProbe/service"
	"fmt"
)

func main() {
	// 初始化日志系统
	log.InitLogger()
	defer log.Close()

	log.Info("==================== GoSecProbe 启动 ====================")

	// 初始化 MySQL 数据库
	err := mysql.InitDB()
	if err != nil {
		log.Fatal("MySQL 初始化失败: %v", err)
	}
	defer mysql.Close()
	log.Info("MySQL 数据库连接成功")

	// 初始化Redis连接
	err = redis.InitRedis(redis.RedisConfig{
		Host:     config.RedisHost,
		Port:     config.RedisPort,
		Password: config.RedisPassword,
		DB:       0,
	})
	if err != nil {
		log.Warn("Redis 连接失败: %v，将在没有 Redis 的情况下继续运行", err)
	} else {
		log.Info("Redis 连接成功")
	}
	defer redis.Close()

	fmt.Println("Starting GoSecProbe API Server...")
	log.Info("启动 GoSecProbe API 服务器，监听端口: 3000")

	// 启动定时任务调度器
	service.StartTaskScheduler()

	r := api.SetupRouter()
	if err := r.Run(":3000"); err != nil {
		log.Fatal("启动服务器失败: %v", err)
	}
}
