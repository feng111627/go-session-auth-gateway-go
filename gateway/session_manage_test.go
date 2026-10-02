package gateway

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// 会话总览：能看到每个活跃会话的入口、建立时间、最近活动时间；
// 刷新与访问都会推进最近活动时间。
func TestSessionOverviewAndActivity(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.IssueWithSource("alice", "web")
	clock.Advance(10 * time.Second)
	pair2 := sm.IssueWithSource("alice", "app")
	sm.IssueWithSource("bob", "web") // 其他账号不应出现在 alice 的总览里

	infos := sm.ListSessions("alice")
	for _, s := range infos {
		t.Logf("总览条目: id=%s source=%s created=%s lastActive=%s suspicious=%v",
			s.ID, s.Source, s.CreatedAt.Format(time.RFC3339), s.LastActiveAt.Format(time.RFC3339), s.Suspicious)
	}
	if len(infos) != 2 {
		t.Fatalf("alice 应有 2 个活跃会话, got %d", len(infos))
	}
	if infos[0].Source != "web" || infos[1].Source != "app" {
		t.Fatalf("总览应按建立时间升序且带来源, got %+v", infos)
	}

	// 访问令牌被使用 -> 最近活动时间推进
	clock.Advance(7 * time.Second)
	res, _ := sm.ValidateAccess(pair2.AccessToken)
	t.Logf("用 app 会话的访问令牌访问 -> 判定: %+v", res)
	got := sm.ListSessions("alice")[1]
	if !got.LastActiveAt.Equal(clock.Now()) {
		t.Fatalf("访问后最近活动时间应更新为 %s, got %s", clock.Now(), got.LastActiveAt)
	}

	// 刷新轮换 -> 最近活动时间同样推进
	clock.Advance(3 * time.Second)
	res, pair3 := sm.Refresh(pair2.RefreshToken)
	t.Logf("app 会话刷新轮换 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("刷新应成功, got %v", res.Reason)
	}
	if got := sm.ListSessions("alice")[1]; !got.LastActiveAt.Equal(clock.Now()) {
		t.Fatalf("轮换后最近活动时间应更新为 %s, got %s", clock.Now(), got.LastActiveAt)
	}
	_ = pair3
}

// 单个结束：令牌立即失效且原因可区分；重复结束/结束不存在的会话幂等且结果稳定。
func TestTerminateSessionSemantics(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	pair := sm.IssueWithSource("alice", "web")
	id, _ := sm.SessionIDOf(pair.AccessToken)
	t.Logf("输入: 结束会话 %s", id)

	tr := sm.TerminateSession("alice", id)
	t.Logf("第一次结束 -> %+v", tr)
	if tr.Status != TerminateDone {
		t.Fatalf("首次结束应为 terminated, got %v", tr.Status)
	}

	// 已发出的访问/刷新令牌立即失效，原因是"用户主动结束"
	res, _ := sm.ValidateAccess(pair.AccessToken)
	t.Logf("结束后用访问令牌 -> 判定: %+v (依据: 会话状态=terminated)", res)
	if res.Reason != ReasonSessionTerminated {
		t.Fatalf("应为 session_terminated, got %v", res.Reason)
	}
	res, _ = sm.Refresh(pair.RefreshToken)
	t.Logf("结束后用刷新令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionTerminated {
		t.Fatalf("应为 session_terminated, got %v", res.Reason)
	}

	// 重复结束：稳定返回 already_ended，不把状态改乱
	tr = sm.TerminateSession("alice", id)
	t.Logf("重复结束 -> %+v", tr)
	if tr.Status != TerminateAlready {
		t.Fatalf("重复结束应为 already_ended, got %v", tr.Status)
	}
	if len(sm.ListSessions("alice")) != 0 {
		t.Fatalf("已结束会话不应出现在活跃总览中")
	}

	// 结束不存在的会话、以及他人会话：not_found，不泄露存在性
	tr = sm.TerminateSession("alice", "no-such-id")
	t.Logf("结束不存在的会话 -> %+v", tr)
	if tr.Status != TerminateNotFound {
		t.Fatalf("应为 not_found, got %v", tr.Status)
	}
	bobPair := sm.IssueWithSource("bob", "web")
	bobID, _ := sm.SessionIDOf(bobPair.AccessToken)
	tr = sm.TerminateSession("alice", bobID)
	t.Logf("alice 结束 bob 的会话 -> %+v", tr)
	if tr.Status != TerminateNotFound {
		t.Fatalf("他人会话应按 not_found 处理, got %v", tr.Status)
	}
	if res, _ := sm.ValidateAccess(bobPair.AccessToken); !res.Allowed {
		t.Fatalf("误伤：bob 的会话不应受影响")
	}
}

// 集中结束：一键结束除当前会话外的所有会话；当前会话不受影响；幂等。
func TestTerminateOtherSessions(t *testing.T) {
	clock := newFakeClock()
	users := []User{{Account: "alice", Password: "pw123", Roles: []string{"reader"}}}
	otp := NewOTPStore(30*time.Second, clock.Now)
	g := NewGateway(
		NewRateLimiter(100, time.Minute, clock.Now),
		NewAuthenticator(users, otp, LoginConfig{MaxFailures: 3, LockDuration: time.Minute}, clock.Now),
		NewSessionManager(time.Minute, time.Hour, clock.Now),
		NewAuthorizer(nil),
	)
	login := func(source string) TokenPair {
		g.Login("alice", source, "pw123")
		code := otp.records["alice"].Code
		_, pair := g.VerifyOTP("alice", source, code)
		return pair
	}
	cur := login("web")
	login("app")
	login("pad")
	t.Logf("输入: alice 有 3 个会话(web/app/pad)，从 web 会话发起一键结束其他会话")

	res, ended := g.TerminateOtherSessions("alice", cur.AccessToken)
	t.Logf("一键结束 -> 判定: %+v, 结束会话数=%d", res, len(ended))
	if !res.Allowed || len(ended) != 2 {
		t.Fatalf("应结束 2 个其他会话, got allowed=%v n=%d", res.Allowed, len(ended))
	}

	infos := g.ListSessions("alice")
	if len(infos) != 1 || infos[0].Source != "web" {
		t.Fatalf("应只剩当前 web 会话, got %+v", infos)
	}
	if res, _ := g.Sessions.ValidateAccess(cur.AccessToken); !res.Allowed {
		t.Fatalf("当前会话不应被误伤")
	}

	// 幂等：再次执行不再结束任何会话
	res, ended = g.TerminateOtherSessions("alice", cur.AccessToken)
	t.Logf("重复一键结束 -> 判定: %+v, 结束会话数=%d", res, len(ended))
	if !res.Allowed || len(ended) != 0 {
		t.Fatalf("重复执行应成功且结束 0 个, got %v n=%d", res.Allowed, len(ended))
	}
}

// 容量回收：到顶后再登录，按"最久未使用"回收；被回收会话立即失效，
// 原因 session_evicted 与用户主动结束可区分。
func TestCapacityEviction(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(2)
	t.Logf("配置: 每账号活跃会话上限=2")

	p1 := sm.IssueWithSource("alice", "web")
	clock.Advance(time.Second)
	p2 := sm.IssueWithSource("alice", "app")
	clock.Advance(time.Second)
	// 用一下 web 会话，让 app 成为"最久未使用"
	if res, _ := sm.ValidateAccess(p1.AccessToken); !res.Allowed {
		t.Fatalf("web 会话应有效")
	}
	t.Logf("输入: web/app 两个会话到顶，web 刚被使用过，再建立第 3 个会话")
	p3 := sm.IssueWithSource("alice", "pad")

	infos := sm.ListSessions("alice")
	for _, s := range infos {
		t.Logf("存活会话: source=%s lastActive=%s", s.Source, s.LastActiveAt.Format(time.RFC3339))
	}
	if len(infos) != 2 || infos[0].Source != "web" || infos[1].Source != "pad" {
		t.Fatalf("应回收最久未使用的 app 会话, got %+v", infos)
	}

	res, _ := sm.ValidateAccess(p2.AccessToken)
	t.Logf("被回收会话的访问令牌 -> 判定: %+v (依据: 状态=evicted)", res)
	if res.Reason != ReasonSessionEvicted {
		t.Fatalf("自动回收应为 session_evicted, got %v", res.Reason)
	}
	res, _ = sm.Refresh(p2.RefreshToken)
	t.Logf("被回收会话的刷新令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionEvicted {
		t.Fatalf("自动回收应为 session_evicted, got %v", res.Reason)
	}
	// 存活会话不受影响
	if res, _ := sm.ValidateAccess(p1.AccessToken); !res.Allowed {
		t.Fatalf("误伤：web 会话应仍有效, got %v", res.Reason)
	}
	if res, _ := sm.ValidateAccess(p3.AccessToken); !res.Allowed {
		t.Fatalf("误伤：pad 会话应仍有效, got %v", res.Reason)
	}
}

// 并发容量：N 个登录同时建立会话，最终活跃数精确等于上限，不超也不少。
func TestConcurrentCapacityEviction(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(3)
	const n = 20
	t.Logf("输入: 上限=3，%d 个并发登录同时建立会话", n)

	pairs := make([]TokenPair, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pairs[i] = sm.IssueWithSource("alice", fmt.Sprintf("src-%d", i))
		}(i)
	}
	wg.Wait()

	infos := sm.ListSessions("alice")
	t.Logf("判定依据: 容量检查与回收在同一把锁内完成，活跃数=%d（上限 3）", len(infos))
	if len(infos) != 3 {
		t.Fatalf("活跃会话数应精确等于上限 3, got %d", len(infos))
	}
	alive := map[string]bool{}
	for _, s := range infos {
		alive[s.ID] = true
	}
	valid, evicted := 0, 0
	for _, p := range pairs {
		res, _ := sm.ValidateAccess(p.AccessToken)
		if res.Allowed {
			valid++
		} else if res.Reason == ReasonSessionEvicted {
			evicted++
		} else {
			t.Fatalf("失效会话应为 session_evicted, got %v", res.Reason)
		}
	}
	t.Logf("并发结果: 有效=%d 被回收=%d", valid, evicted)
	if valid != 3 || evicted != n-3 {
		t.Fatalf("应 3 个有效、%d 个被回收, got valid=%d evicted=%d", n-3, valid, evicted)
	}
}

// 并发结束与刷新：结束与多个刷新同时进行，最终会话必为已结束，
// 之后任何令牌都不能再放行，且不会出现"结束后又刷新成功"的自相矛盾。
func TestConcurrentTerminateAndRefresh(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	pair := sm.IssueWithSource("alice", "web")
	id, _ := sm.SessionIDOf(pair.AccessToken)
	t.Logf("输入: 1 个结束请求与 8 个刷新请求并发打到同一会话 %s", id)

	var wg sync.WaitGroup
	results := make([]Result, 8)
	wg.Add(1)
	go func() { defer wg.Done(); sm.TerminateSession("alice", id) }()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, _ := sm.Refresh(pair.RefreshToken)
			results[i] = res
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		t.Logf("并发刷新 %d -> allowed=%v reason=%v", i, r.Allowed, r.Reason)
	}

	// 无论并发时序如何，结束后当前刷新令牌必不能放行
	res, _ := sm.Refresh(pair.RefreshToken)
	t.Logf("尘埃落定后再刷新 -> 判定: %+v", res)
	if res.Reason != ReasonSessionTerminated {
		t.Fatalf("结束后刷新应为 session_terminated, got %v", res.Reason)
	}
	if len(sm.ListSessions("alice")) != 0 {
		t.Fatalf("结束后不应有活跃会话")
	}
}

// 审计追溯：建立/轮换/结束/回收/可疑都按账号可查，且带判定依据与当时配置快照；
// 配置调整后，历史事件仍按当时规则解释。
func TestSessionAuditEvents(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(1)
	t.Logf("配置: 上限=1 accessTTL=1m refreshTTL=1h")

	p1 := sm.IssueWithSource("alice", "web")
	sm.Refresh(p1.RefreshToken)              // 一次轮换
	p2 := sm.IssueWithSource("alice", "app") // 触发回收 p1
	sm.TerminateSession("alice", mustSessionID(t, sm, p2))
	// 重放检测 -> 可疑事件
	p3 := sm.IssueWithSource("alice", "pad")
	old := p3.RefreshToken
	sm.Refresh(old)
	clock.Advance(10 * time.Second)
	sm.Refresh(old)

	// 改配置：历史事件的快照不应被改写
	sm.SetMaxSessions(99)

	events := sm.Events("alice")
	var kinds []EventKind
	for _, e := range events {
		kinds = append(kinds, e.Kind)
		t.Logf("事件: kind=%s session=%s detail=%s snapshot.maxSessions=%d",
			e.Kind, e.SessionID[:8], e.Detail, e.Config.MaxSessionsPerAccount)
	}
	// 顺序依据：建立新会话前先回收腾位，因此 evicted 在第二个 created 之前
	want := []EventKind{EventCreated, EventRotated, EventEvicted, EventCreated,
		EventTerminated, EventCreated, EventRotated, EventSuspicious}
	if len(kinds) != len(want) {
		t.Fatalf("事件数不符: got %v want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("第 %d 个事件应为 %s, got %s", i, want[i], kinds[i])
		}
	}
	// 历史快照：回收事件记录的上限应是当时的 1，而不是改后的 99
	for _, e := range events {
		if e.Kind == EventEvicted && e.Config.MaxSessionsPerAccount != 1 {
			t.Fatalf("回收事件快照应为当时的上限 1, got %d", e.Config.MaxSessionsPerAccount)
		}
		if e.Config.AccessTTL != time.Minute || e.Config.RefreshTTL != time.Hour {
			t.Fatalf("事件快照应带当时有效期配置, got %+v", e.Config)
		}
	}
}

func mustSessionID(t *testing.T, sm *SessionManager, p TokenPair) string {
	t.Helper()
	id, ok := sm.SessionIDOf(p.AccessToken)
	if !ok {
		t.Fatalf("应能定位会话")
	}
	return id
}
