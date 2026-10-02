package gateway

import (
	"fmt"
	"sync"
	"time"
)

// windowCounter 某个 (账号, 来源) 在当前窗口内的计数。
type windowCounter struct {
	windowStart time.Time
	count       int
}

// RateLimiter 按 账号+来源 做固定窗口限流。
// 计数与窗口翻转在同一把互斥锁内完成，并发下不会多放行也不会少放行。
type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	clock    Clock
	counters map[string]*windowCounter // "account|source" -> 计数器
}

// NewRateLimiter 创建限流器：每个窗口内每个 (账号, 来源) 最多放行 limit 次。
func NewRateLimiter(limit int, window time.Duration, clock Clock) *RateLimiter {
	if clock == nil {
		clock = realClock
	}
	return &RateLimiter{limit: limit, window: window, clock: clock, counters: make(map[string]*windowCounter)}
}

// Allow 判断 (account, source) 这一次请求是否放行。
// 放行即消耗一个配额；窗口过期后自动重置。
func (l *RateLimiter) Allow(account, source string) Result {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := account + "|" + source
	now := l.clock()
	c, ok := l.counters[key]
	if !ok || !now.Before(c.windowStart.Add(l.window)) {
		c = &windowCounter{windowStart: now}
		l.counters[key] = c
	}
	if c.count >= l.limit {
		return Reject(ReasonRateLimited,
			fmt.Sprintf("账号 %s 来源 %s 在窗口内已达上限 %d 次", account, source, l.limit))
	}
	c.count++
	return Allow(fmt.Sprintf("限流通过（窗口内第 %d/%d 次）", c.count, l.limit))
}
