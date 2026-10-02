package gateway

import (
	"sync"
	"testing"
	"time"
)

func TestConcurrentRefreshOnlyOneSucceeds(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	pair := sm.Issue("alice", "test")
	t.Logf("输入: 初始刷新令牌 %s，并发 %d 个请求同时刷新", pair.RefreshToken, 16)

	const n = 16
	results := make([]Result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, _ := sm.Refresh(pair.RefreshToken)
			results[i] = res
		}(i)
	}
	wg.Wait()

	succeeded := 0
	for i, r := range results {
		t.Logf("请求 %d -> allowed=%v reason=%v detail=%s", i, r.Allowed, r.Reason, r.Detail)
		if r.Allowed {
			succeeded++
		}
	}
	t.Logf("判定依据: 轮换在互斥锁内完成，只有第一个请求看到的是当前令牌")
	if succeeded != 1 {
		t.Fatalf("并发刷新应只成功 1 次, got %d", succeeded)
	}
	if sm.IsSuspicious(pair.RefreshToken) {
		t.Fatalf("宽限期内的并发重复不应标记会话族可疑")
	}
}

func TestRefreshTokenReplayRevokesFamily(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	pair := sm.Issue("alice", "test")
	oldRefresh := pair.RefreshToken

	res, pair2 := sm.Refresh(oldRefresh)
	t.Logf("正常轮换 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("首次刷新应成功, got %v", res.Reason)
	}

	// 宽限期过后重放旧令牌
	clock.Advance(10 * time.Second)
	res, _ = sm.Refresh(oldRefresh)
	t.Logf("宽限期外重放旧刷新令牌 -> 判定: %+v (依据: 令牌非当前且超出宽限期)", res)
	if res.Reason != ReasonRefreshReused {
		t.Fatalf("重放应为 refresh_reused, got %v", res.Reason)
	}
	if !sm.IsSuspicious(oldRefresh) {
		t.Fatalf("会话族应被标记为可疑")
	}

	// 撤销后，新刷新令牌与访问令牌都不能再用
	res, _ = sm.Refresh(pair2.RefreshToken)
	t.Logf("撤销后用新刷新令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionRevoked {
		t.Fatalf("撤销后应为 session_revoked, got %v", res.Reason)
	}
	res, _ = sm.ValidateAccess(pair2.AccessToken)
	t.Logf("撤销后用其访问令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionRevoked {
		t.Fatalf("撤销后访问令牌应为 session_revoked, got %v", res.Reason)
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	pair := sm.Issue("alice", "test")

	res, account := sm.ValidateAccess(pair.AccessToken)
	t.Logf("有效期内访问令牌 -> 判定: %+v account=%s", res, account)
	if !res.Allowed || account != "alice" {
		t.Fatalf("有效期内应通过, got %v", res.Reason)
	}

	clock.Advance(61 * time.Second)
	res, _ = sm.ValidateAccess(pair.AccessToken)
	t.Logf("过期访问令牌 -> 判定: %+v (依据: 已过 61s > accessTTL 60s)", res)
	if res.Reason != ReasonTokenExpired {
		t.Fatalf("过期应为 token_expired, got %v", res.Reason)
	}
}
