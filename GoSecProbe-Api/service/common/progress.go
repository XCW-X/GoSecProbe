package common

import (
	"sync"
	"sync/atomic"
)

// ProgressReporter 进度报告器接口
type ProgressReporter interface {
	// ReportProgress 报告进度
	// current: 当前完成数量
	// total: 总数量
	// message: 当前状态消息
	ReportProgress(current, total int, message string)

	// ReportTargetScanned 报告单个目标扫描完成
	// target: 目标标识（IP、域名等）
	// found: 是否发现有效结果（如：存活、有开放端口等）
	ReportTargetScanned(target string, found bool)
}

// ProgressTracker 进度跟踪器，线程安全
type ProgressTracker struct {
	mu              sync.RWMutex
	totalTargets    int64
	scannedTargets  int64
	foundAssets     int64
	currentTarget   string
	onProgressFunc  func(current, total, found int, currentTarget, message string)
	updateThreshold int // 更新阈值，避免过于频繁的回调
	updateCounter   int64
}

// NewProgressTracker 创建进度跟踪器
func NewProgressTracker(totalTargets int, onProgress func(current, total, found int, currentTarget, message string)) *ProgressTracker {
	return &ProgressTracker{
		totalTargets:    int64(totalTargets),
		scannedTargets:  0,
		foundAssets:     0,
		onProgressFunc:  onProgress,
		updateThreshold: 10, // 默认每10个目标更新一次
	}
}

// SetUpdateThreshold 设置更新阈值
func (p *ProgressTracker) SetUpdateThreshold(threshold int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updateThreshold = threshold
}

// ReportProgress 实现 ProgressReporter 接口
func (p *ProgressTracker) ReportProgress(current, total int, message string) {
	if p.onProgressFunc != nil {
		found := int(atomic.LoadInt64(&p.foundAssets))
		p.mu.RLock()
		currentTarget := p.currentTarget
		p.mu.RUnlock()
		p.onProgressFunc(current, total, found, currentTarget, message)
	}
}

// ReportTargetScanned 实现 ProgressReporter 接口
func (p *ProgressTracker) ReportTargetScanned(target string, found bool) {
	// 原子递增已扫描数
	scanned := atomic.AddInt64(&p.scannedTargets, 1)

	// 如果发现有效结果，递增发现数
	if found {
		atomic.AddInt64(&p.foundAssets, 1)
	}

	// 更新当前目标
	p.mu.Lock()
	p.currentTarget = target
	p.mu.Unlock()

	// 检查是否需要触发回调（避免过于频繁）
	counter := atomic.AddInt64(&p.updateCounter, 1)
	total := atomic.LoadInt64(&p.totalTargets)

	shouldUpdate := false
	p.mu.RLock()
	threshold := p.updateThreshold
	p.mu.RUnlock()

	// 满足以下条件之一则更新：
	// 1. 达到更新阈值
	// 2. 是最后一个目标
	// 3. 发现了有效结果
	if counter%int64(threshold) == 0 || scanned == total || found {
		shouldUpdate = true
	}

	if shouldUpdate && p.onProgressFunc != nil {
		foundCount := int(atomic.LoadInt64(&p.foundAssets))
		message := ""
		if found {
			message = "发现有效结果"
		}
		p.onProgressFunc(int(scanned), int(total), foundCount, target, message)
	}
}

// GetProgress 获取当前进度
func (p *ProgressTracker) GetProgress() (scanned, total, found int, currentTarget string) {
	scanned = int(atomic.LoadInt64(&p.scannedTargets))
	total = int(atomic.LoadInt64(&p.totalTargets))
	found = int(atomic.LoadInt64(&p.foundAssets))
	p.mu.RLock()
	currentTarget = p.currentTarget
	p.mu.RUnlock()
	return
}

// SetTotal 设置总目标数（用于动态调整）
func (p *ProgressTracker) SetTotal(total int) {
	atomic.StoreInt64(&p.totalTargets, int64(total))
}

// Reset 重置进度
func (p *ProgressTracker) Reset() {
	atomic.StoreInt64(&p.scannedTargets, 0)
	atomic.StoreInt64(&p.foundAssets, 0)
	atomic.StoreInt64(&p.updateCounter, 0)
	p.mu.Lock()
	p.currentTarget = ""
	p.mu.Unlock()
}
