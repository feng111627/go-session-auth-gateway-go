package gateway

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 回归：到上限后再登录，若新旧会话时间戳完全相同（同一秒/时钟未推进），
// 被回收的必须是旧会话，刚建立的会话必须存活且可用。
// 重复多轮以覆盖会话 ID 字典序并列的各种组合（旧实现按随机 ID 并列时
// 可能把新会话回收掉）。
func TestNewSessionSurvivesEvictionAtSameTimestamp(t *testing.T) {
	for round := 0; round < 50; round++ {
		clock := newFakeClock() // 时钟冻结：所有会话建立/活动时间完全相同
		sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
		sm.SetMaxSessions(1)

		old := sm.Issue("alice", "web")
		fresh := sm.Issue("alice", "mobile") // 同一时刻触发回收

		res, _ := sm.ValidateAccess(fresh.AccessToken)
		if !res.Allowed {
			t.Fatalf("第 %d 轮: 刚登录的会话被误回收: %v (%s)", round, res.Reason, res.Detail)
		}
		res, _ = sm.ValidateAccess(old.AccessToken)
		if res.Reason != ReasonSessionEvicted {
			t.Fatalf("第 %d 轮: 旧会话应被回收(session_evicted), got %v", round, res.Reason)
		}
		if got := len(sm.ListSessions("alice")); got != 1 {
			t.Fatalf("第 %d 轮: 活跃会话数应为上限 1, got %d", round, got)
		}
	}
	t.Logf("判定依据: 50 轮同一时间戳下，刚建立的会话全部存活，旧会话全部以 session_evicted 回收")
}

// 并列清理顺序可预期：最近活动时间相同（同一时刻都被使用过）时，
// 建立时间早的旧会话优先被回收，而不是随机挑选。
func TestEvictionTieBreakByCreatedAt(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(2)

	older := sm.Issue("alice", "web") // 建立于 t0
	clock.Advance(time.Second)
	newer := sm.Issue("alice", "mobile") // 建立于 t1
	// 同一时刻 t2 两个会话都被使用 -> 最近活动时间并列
	clock.Advance(time.Second)
	if res, _ := sm.ValidateAccess(older.AccessToken); !res.Allowed {
		t.Fatalf("web 会话应有效: %v", res.Reason)
	}
	if res, _ := sm.ValidateAccess(newer.AccessToken); !res.Allowed {
		t.Fatalf("mobile 会话应有效: %v", res.Reason)
	}
	sm.Issue("alice", "desktop") // t2 建立，触发回收

	infos := sm.ListSessions("alice")
	for _, in := range infos {
		t.Logf("存活会话: 入口=%s 建立=%s 最近活动=%s",
			in.Source, in.CreatedAt.Format(time.RFC3339), in.LastActiveAt.Format(time.RFC3339))
	}
	if len(infos) != 2 {
		t.Fatalf("活跃会话数应为上限 2, got %d", len(infos))
	}
	// 最近活动并列 -> 建立早的 web 被回收，mobile 与新建的 desktop 存活
	if infos[0].Source != "mobile" || infos[1].Source != "desktop" {
		t.Fatalf("最近活动并列时应回收建立最早的 web, got %+v", infos)
	}
	res, _ := sm.ValidateAccess(older.AccessToken)
	t.Logf("被回收的 web 会话访问令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionEvicted {
		t.Fatalf("web 应为 session_evicted, got %v", res.Reason)
	}
}

// 并发登录且时钟冻结（所有会话时间戳相同）：每次登录都保住自己刚建的会话，
// 最终活跃数等于上限；存活会话无一被误伤，被回收会话全部以 session_evicted 拒绝。
func TestConcurrentLoginsAtSameTimestamp(t *testing.T) {
	clock := newFakeClock() // 冻结：所有登录落在同一时刻
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	const cap = 3
	sm.SetMaxSessions(cap)

	const n = 64
	pairs := make([]TokenPair, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pairs[i] = sm.Issue("alice", fmt.Sprintf("entry-%d", i))
		}(i)
	}
	wg.Wait()

	infos := sm.ListSessions("alice")
	t.Logf("输入: 同一时刻并发 %d 次登录, 上限 %d -> 活跃会话数 %d", n, cap, len(infos))
	if len(infos) != cap {
		t.Fatalf("活跃会话数应正好为上限 %d, got %d", cap, len(infos))
	}
	active := map[string]bool{}
	for _, in := range infos {
		active[in.ID] = true
	}
	valid, evicted := 0, 0
	for _, p := range pairs {
		fid, _ := sm.FamilyIDOf(p.AccessToken)
		res, _ := sm.ValidateAccess(p.AccessToken)
		if active[fid] {
			if !res.Allowed {
				t.Fatalf("存活会话 %s 被误伤: %v", fid[:8], res.Reason)
			}
			valid++
		} else {
			if res.Reason != ReasonSessionEvicted {
				t.Fatalf("被回收会话应为 session_evicted, got %v", res.Reason)
			}
			evicted++
		}
	}
	t.Logf("判定: 存活 %d 个全部有效，回收 %d 个全部 session_evicted，无误伤", valid, evicted)
}

// 容量回收只影响超额的旧会话：未到上限时一个都不回收，
// 有效会话不会被误伤。
func TestNoEvictionBelowCapacity(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(3)

	p1 := sm.Issue("alice", "web")
	clock.Advance(time.Second)
	p2 := sm.Issue("alice", "mobile")
	clock.Advance(time.Second)
	p3 := sm.Issue("alice", "desktop") // 正好到上限，不应触发任何回收

	for i, p := range []TokenPair{p1, p2, p3} {
		res, _ := sm.ValidateAccess(p.AccessToken)
		t.Logf("会话 %d 访问令牌 -> 判定: %+v", i, res)
		if !res.Allowed {
			t.Fatalf("会话 %d 不应被回收: %v", i, res.Reason)
		}
	}
	if got := len(sm.ListSessions("alice")); got != 3 {
		t.Fatalf("3 个会话都应存活, got %d", got)
	}
}
