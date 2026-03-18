package log

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LogLevel 日志级别
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

var levelNames = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

// Logger 日志器结构
type Logger struct {
	mu          sync.Mutex
	level       LogLevel
	file        *os.File
	logDir      string
	maxSize     int64 // 单个日志文件最大大小（字节）
	maxBackups  int   // 保留的旧日志文件数量
	currentSize int64
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// InitLogger 初始化日志系统
func InitLogger() {
	once.Do(func() {
		logDir := "./logs"
		if err := os.MkdirAll(logDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "创建日志目录失败: %v\n", err)
			os.Exit(1)
		}

		defaultLogger = &Logger{
			level:      INFO,
			logDir:     logDir,
			maxSize:    10 * 1024 * 1024, // 10MB
			maxBackups: 10,
		}

		if err := defaultLogger.openLogFile(); err != nil {
			fmt.Fprintf(os.Stderr, "初始化日志文件失败: %v\n", err)
			os.Exit(1)
		}

		Info("[日志系统] 已初始化，日志目录: %s", logDir)
	})
}

// openLogFile 打开日志文件
func (l *Logger) openLogFile() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 关闭旧文件
	if l.file != nil {
		l.file.Close()
	}

	// 创建新日志文件
	filename := filepath.Join(l.logDir, fmt.Sprintf("GoSecProbe_%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}

	// 获取文件大小
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("获取文件信息失败: %v", err)
	}

	l.file = file
	l.currentSize = stat.Size()

	return nil
}

// rotateLog 日志轮转
func (l *Logger) rotateLog() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Close()
	}

	// 生成备份文件名
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	oldName := filepath.Join(l.logDir, fmt.Sprintf("GoSecProbe_%s.log", time.Now().Format("2006-01-02")))
	newName := filepath.Join(l.logDir, fmt.Sprintf("GoSecProbe_%s.log", timestamp))

	// 重命名当前文件
	if err := os.Rename(oldName, newName); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("重命名日志文件失败: %v", err)
	}

	// 清理旧日志文件
	l.cleanOldLogs()

	// 创建新文件
	return l.openLogFile()
}

// cleanOldLogs 清理旧日志文件
func (l *Logger) cleanOldLogs() {
	files, err := filepath.Glob(filepath.Join(l.logDir, "GoSecProbe_*.log"))
	if err != nil {
		return
	}

	if len(files) <= l.maxBackups {
		return
	}

	// 删除最旧的文件
	for i := 0; i < len(files)-l.maxBackups; i++ {
		os.Remove(files[i])
	}
}

// checkRotate 检查是否需要轮转
func (l *Logger) checkRotate() {
	if l.currentSize >= l.maxSize {
		if err := l.rotateLog(); err != nil {
			fmt.Fprintf(os.Stderr, "日志轮转失败: %v\n", err)
		}
	}
}

// log 记录日志
func (l *Logger) log(level LogLevel, format string, v ...interface{}) {
	if level < l.level {
		return
	}

	// 格式化日志消息
	message := fmt.Sprintf(format, v...)
	logLine := fmt.Sprintf("%s [%s] %s\n",
		time.Now().Format("2006/01/02 15:04:05"),
		levelNames[level],
		message)

	l.mu.Lock()
	defer l.mu.Unlock()

	// 同时输出到控制台和文件
	fmt.Print(logLine)
	if l.file != nil {
		l.file.WriteString(logLine)
	}

	// 更新当前文件大小
	l.currentSize += int64(len(logLine))

	// 检查是否需要轮转
	go l.checkRotate()
}

// SetLevel 设置日志级别
func SetLevel(level LogLevel) {
	if defaultLogger != nil {
		defaultLogger.level = level
	}
}

// Debug 调试日志
func Debug(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(DEBUG, format, v...)
	}
}

// Info 信息日志
func Info(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(INFO, format, v...)
	}
}

// Warn 警告日志
func Warn(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(WARN, format, v...)
	}
}

// Error 错误日志
func Error(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(ERROR, format, v...)
	}
}

// Fatal 致命错误日志
func Fatal(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.log(FATAL, format, v...)
		os.Exit(1)
	}
}

// Close 关闭日志系统
func Close() {
	if defaultLogger != nil && defaultLogger.file != nil {
		defaultLogger.mu.Lock()
		defer defaultLogger.mu.Unlock()
		defaultLogger.file.Close()
	}
}

// Debugf 调试日志（兼容标准库）
func Debugf(format string, v ...interface{}) {
	Debug(format, v...)
}

// Infof 信息日志（兼容标准库）
func Infof(format string, v ...interface{}) {
	Info(format, v...)
}

// Warnf 警告日志（兼容标准库）
func Warnf(format string, v ...interface{}) {
	Warn(format, v...)
}

// Errorf 错误日志（兼容标准库）
func Errorf(format string, v ...interface{}) {
	Error(format, v...)
}

// Fatalf 致命错误日志（兼容标准库）
func Fatalf(format string, v ...interface{}) {
	Fatal(format, v...)
}

// Printf 普通日志（默认INFO级别）
func Printf(format string, v ...interface{}) {
	Info(format, v...)
}

// Print 普通日志（兼容标准库，默认INFO级别）
func Print(v ...interface{}) {
	Info(fmt.Sprint(v...))
}

// Println 普通日志（兼容标准库，默认INFO级别）
func Println(v ...interface{}) {
	Info(fmt.Sprint(v...))
}

// Panicf 触发panic的日志
func Panicf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	Error(msg)
	panic(msg)
}

// Panic 触发panic的日志（兼容标准库）
func Panic(v ...interface{}) {
	msg := fmt.Sprint(v...)
	Error(msg)
	panic(msg)
}

// Panicln 触发panic的日志（兼容标准库）
func Panicln(v ...interface{}) {
	msg := fmt.Sprint(v...)
	Error(msg)
	panic(msg)
}
