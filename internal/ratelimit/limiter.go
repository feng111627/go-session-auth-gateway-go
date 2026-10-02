package ratelimit

import (
	"sync"
	"time"
)

// 限流命中的维度（可作为拒绝原因被断言区分）。
const (
	ReasonAccountLimited = "rate_limited_account"
	ReasonSourceLimited  = "rate_limited_source"
)

// Verdict 一次限流判定的结果与解释信息。
type Verdict struct {
	Allowed    bool
	Reason     string        // 被拒时的维度原因；放行时为空
	Remaining  int           // 放行后该请求所命中维度的剩余额度（以账号维度为准）
	RetryAfter time.Duration // 被拒时距窗口重置的等待时间
}

// window 是单个 key 的固定窗口计数。
type window struct {
	start time.Time
	count int
}

// Limiter 按账号与来源两个维度做固定窗口限流。
// 每次请求在两个维度上各占 1 个额度，任一维度超限即拒绝；
// 被拒绝的请求不消耗任何维度的额度。
type Limiter struct {
	mu sync.Mutex

	accountLimit int
	sourceLimit  int
	windowLen    time.Duration
	now          func() time.Time

	accounts map[string]*window
	sources  map[string]*window
}

func New(accountLimit, sourceLimit int, windowLen time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		accountLimit: accountLimit,
		sourceLimit:  sourceLimit,
		windowLen:    windowLen,
		now:          now,
		accounts:     make(map[string]*window),
		sources:      make(map[string]*window),
	}
}

// Check 在时刻 t 对 (account, source) 做一次限流判定。
// 两个维度的预检与计数递增都在同一把互斥锁内完成：
// 任一维度窗口已满 -> 拒绝且不递增任何计数；
// 两个维度都有余量 -> 同一临界区内同时递增，保证并发 N 个请求时，
// 每个维度恰好放行前 limit 个，不会多放也不会少放。
func (l *Limiter) Check(account, source string, t time.Time) Verdict {
	l.mu.Lock()
	defer l.mu.Unlock()

	wa := l.accounts[account]
	if wa == nil {
		wa = &window{start: t}
		l.accounts[account] = wa
	}
	if !t.Before(wa.start.Add(l.windowLen)) {
		wa.start, wa.count = t, 0
	}

	ws := l.sources[source]
	if ws == nil {
		ws = &window{start: t}
		l.sources[source] = ws
	}
	if !t.Before(ws.start.Add(l.windowLen)) {
		ws.start, ws.count = t, 0
	}

	// 预检（不递增）。账号维度优先上报，保持原因稳定可解释。
	if wa.count >= l.accountLimit {
		return Verdict{Allowed: false, Reason: ReasonAccountLimited,
			Remaining: 0, RetryAfter: retryAfter(wa, l.windowLen, t)}
	}
	if ws.count >= l.sourceLimit {
		return Verdict{Allowed: false, Reason: ReasonSourceLimited,
			Remaining: 0, RetryAfter: retryAfter(ws, l.windowLen, t)}
	}

	// 两维度同时提交。
	wa.count++
	ws.count++
	return Verdict{Allowed: true, Remaining: l.accountLimit - wa.count}
}

func retryAfter(w *window, windowLen time.Duration, t time.Time) time.Duration {
	d := w.start.Add(windowLen).Sub(t)
	if d < 0 {
		return 0
	}
	return d
}
