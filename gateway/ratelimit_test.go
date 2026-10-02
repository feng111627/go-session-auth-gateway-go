package gateway

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimitBoundary(t *testing.T) {
	clock := newFakeClock()
	rl := NewRateLimiter(3, time.Minute, clock.Now)

	for i := 1; i <= 3; i++ {
		res := rl.Allow("alice", "web")
		t.Logf("窗口内第 %d 次请求 -> 判定: %+v", i, res)
		if !res.Allowed {
			t.Fatalf("第 %d 次应放行, got %v", i, res.Reason)
		}
	}
	res := rl.Allow("alice", "web")
	t.Logf("第 4 次请求 -> 判定: %+v (依据: 已达上限 3)", res)
	if res.Reason != ReasonRateLimited {
		t.Fatalf("超限应为 rate_limited, got %v", res.Reason)
	}

	// 不同来源独立计数
	res = rl.Allow("alice", "mobile")
	t.Logf("同一账号换来源 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("不同来源应独立计数, got %v", res.Reason)
	}

	// 窗口过后重置
	clock.Advance(61 * time.Second)
	res = rl.Allow("alice", "web")
	t.Logf("窗口过期后 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("窗口重置后应放行, got %v", res.Reason)
	}
}

func TestRateLimitConcurrentExact(t *testing.T) {
	clock := newFakeClock()
	const limit = 50
	rl := NewRateLimiter(limit, time.Minute, clock.Now)

	const n = 200 // 远超上限的并发请求
	allowed := make([]bool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			allowed[i] = rl.Allow("alice", "web").Allowed
		}(i)
	}
	wg.Wait()

	count := 0
	for _, a := range allowed {
		if a {
			count++
		}
	}
	t.Logf("输入: 上限 %d，并发 %d 个请求 -> 放行 %d 次 (依据: 计数在互斥锁内完成)", limit, n, count)
	if count != limit {
		t.Fatalf("并发下放行数应精确等于上限 %d, got %d", limit, count)
	}
}
