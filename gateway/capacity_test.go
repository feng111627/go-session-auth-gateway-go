package gateway

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 容量回收规则：到顶后再登录，按"最近最久未使用"回收旧会话，规则可预期。
func TestCapacityEvictsLeastRecentlyUsed(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(2)

	sm.Issue("alice", "web") // t0
	clock.Advance(time.Second)
	p2 := sm.Issue("alice", "mobile") // t1
	// 让 mobile 会话在 t2 被使用，web 成为最久未使用
	clock.Advance(time.Second)
	if res, _ := sm.ValidateAccess(p2.AccessToken); !res.Allowed {
		t.Fatalf("mobile 会话应有效: %v", res.Reason)
	}
	clock.Advance(time.Second)
	sm.Issue("alice", "desktop") // t3，触发回收

	infos := sm.ListSessions("alice")
	for _, in := range infos {
		t.Logf("存活会话: 入口=%s 最近活动=%s", in.Source, in.LastActiveAt.Format(time.RFC3339))
	}
	if len(infos) != 2 {
		t.Fatalf("活跃会话数不应超过上限 2, got %d", len(infos))
	}
	if infos[0].Source != "mobile" || infos[1].Source != "desktop" {
		t.Fatalf("应回收最久未使用的 web 会话, got %+v", infos)
	}
}

// 被回收的会话：令牌立即失效，原因 session_evicted，与用户主动结束可区分；
// 且留下带判定依据的回收事件。
func TestEvictedSessionInvalidatedAndTraceable(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(1)

	p1 := sm.Issue("alice", "web")
	clock.Advance(time.Second)
	sm.Issue("alice", "mobile") // 触发回收 web（web 最久未使用）

	res, _ := sm.ValidateAccess(p1.AccessToken)
	t.Logf("被回收会话的访问令牌 -> 判定: %+v (依据: endKind=evicted)", res)
	if res.Reason != ReasonSessionEvicted {
		t.Fatalf("应为 session_evicted, got %v", res.Reason)
	}
	res, _ = sm.Refresh(p1.RefreshToken)
	t.Logf("被回收会话的刷新令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionEvicted {
		t.Fatalf("应为 session_evicted, got %v", res.Reason)
	}

	// 与用户主动结束区分
	clock.Advance(time.Second)
	p2 := sm.Issue("alice", "desktop") // 回收 mobile
	sid := sm.ListSessions("alice")[0].ID
	sm.EndSession("alice", sid)
	res, _ = sm.ValidateAccess(p2.AccessToken)
	t.Logf("用户结束会话的访问令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionEndedByUser {
		t.Fatalf("应为 session_ended_by_user, got %v", res.Reason)
	}

	// 回收事件可追溯，含判定依据
	var evicted []SessionEvent
	for _, e := range sm.Events("alice") {
		if e.Kind == EventEvicted {
			evicted = append(evicted, e)
			t.Logf("回收事件: 会话=%s 依据=%q 当时上限=%d", e.FamilyID[:8], e.Detail, e.MaxSessions)
		}
	}
	if len(evicted) != 2 {
		t.Fatalf("应有 2 条回收事件, got %d", len(evicted))
	}
}

// 并发登录：任何时刻与最终状态下，活跃会话数都不超过上限。
func TestConcurrentLoginsNeverExceedCapacity(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	const cap = 3
	sm.SetMaxSessions(cap)

	const n = 32
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
	t.Logf("并发 %d 次登录后活跃会话数=%d（上限 %d）", n, len(infos), cap)
	if len(infos) != cap {
		t.Fatalf("活跃会话数应正好为上限 %d, got %d", cap, len(infos))
	}
	// 存活的会话凭证必须有效，被回收的必须失效且原因可区分
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
	t.Logf("判定: 存活 %d 个全部有效，回收 %d 个全部以 session_evicted 拒绝", valid, evicted)
}

// 并发混合：登录、结束、刷新同时进行，最终状态自洽——
// 活跃数不超上限，失效会话不再放行，存活会话不被误伤。
func TestConcurrentMixedOperationsStayConsistent(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	const cap = 4
	sm.SetMaxSessions(cap)

	var mu sync.Mutex
	var pairs []TokenPair
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0: // 登录
				p := sm.Issue("alice", "web")
				mu.Lock()
				pairs = append(pairs, p)
				mu.Unlock()
			case 1: // 结束某个已知会话（可能已不存在/已结束，幂等）
				mu.Lock()
				var target string
				if len(pairs) > 0 {
					target, _ = sm.FamilyIDOf(pairs[0].AccessToken)
				}
				mu.Unlock()
				if target != "" {
					sm.EndSession("alice", target)
				}
			case 2: // 刷新某个已知会话的刷新令牌
				mu.Lock()
				var rt string
				if len(pairs) > 0 {
					rt = pairs[len(pairs)-1].RefreshToken
				}
				mu.Unlock()
				if rt != "" {
					sm.Refresh(rt)
				}
			}
		}(i)
	}
	wg.Wait()

	infos := sm.ListSessions("alice")
	t.Logf("并发混合操作后活跃会话数=%d（上限 %d）", len(infos), cap)
	if len(infos) > cap {
		t.Fatalf("活跃会话数超过上限: %d > %d", len(infos), cap)
	}
	active := map[string]bool{}
	for _, in := range infos {
		active[in.ID] = true
	}
	for _, p := range pairs {
		fid, _ := sm.FamilyIDOf(p.AccessToken)
		res, _ := sm.ValidateAccess(p.AccessToken)
		if active[fid] && !res.Allowed {
			t.Fatalf("存活会话 %s 被误伤: %v", fid[:8], res.Reason)
		}
		if !active[fid] && res.Allowed {
			t.Fatalf("已失效会话 %s 不应放行", fid[:8])
		}
	}
	t.Logf("判定: %d 个存活会话全部有效，失效会话无一放行", len(infos))
}
