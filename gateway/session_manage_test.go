package gateway

import (
	"testing"
	"time"
)

// 会话总览：多入口登录后能看到每个活跃会话的入口、建立与最近活动时间。
func TestListSessionsOverview(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	p1 := sm.Issue("alice", "web")
	clock.Advance(2 * time.Second)
	sm.Issue("alice", "mobile")
	clock.Advance(3 * time.Second)
	sm.Issue("bob", "web")

	// alice 用第一个会话的访问令牌访问资源，刷新其最近活动时间
	clock.Advance(4 * time.Second)
	res, _ := sm.ValidateAccess(p1.AccessToken)
	t.Logf("输入: 用 web 会话的访问令牌访问 -> 判定: %+v", res)

	infos := sm.ListSessions("alice")
	if len(infos) != 2 {
		t.Fatalf("alice 应有 2 个活跃会话, got %d", len(infos))
	}
	for _, in := range infos {
		t.Logf("会话 %s: 入口=%s 建立=%s 最近活动=%s 可疑=%v",
			in.ID[:8], in.Source, in.CreatedAt.Format(time.RFC3339),
			in.LastActiveAt.Format(time.RFC3339), in.Suspicious)
	}
	// 按建立时间升序：web 在前，mobile 在后
	if infos[0].Source != "web" || infos[1].Source != "mobile" {
		t.Fatalf("总览顺序或入口不对: %+v", infos)
	}
	if !infos[0].LastActiveAt.After(infos[0].CreatedAt) {
		t.Fatalf("访问资源后最近活动时间应更新: created=%s last=%s",
			infos[0].CreatedAt, infos[0].LastActiveAt)
	}
	if got := len(sm.ListSessions("bob")); got != 1 {
		t.Fatalf("bob 应有 1 个活跃会话, got %d", got)
	}
}

// 单独结束：令牌立即失效且原因可区分；重复结束/不存在/已结束都稳定不出错。
func TestEndSessionIdempotent(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	pair := sm.Issue("alice", "web")
	infos := sm.ListSessions("alice")
	sid := infos[0].ID

	res, out := sm.EndSession("alice", sid)
	t.Logf("第一次结束 -> 判定: %+v outcome=%s", res, out)
	if out != EndOutcomeEnded || !res.Allowed {
		t.Fatalf("首次结束应为 ended_now, got %s", out)
	}

	// 访问令牌与刷新令牌立即失效，原因是"用户主动结束"
	res, _ = sm.ValidateAccess(pair.AccessToken)
	t.Logf("结束后用访问令牌 -> 判定: %+v (依据: endKind=ended_by_user)", res)
	if res.Reason != ReasonSessionEndedByUser {
		t.Fatalf("应为 session_ended_by_user, got %v", res.Reason)
	}
	res, _ = sm.Refresh(pair.RefreshToken)
	t.Logf("结束后用刷新令牌 -> 判定: %+v", res)
	if res.Reason != ReasonSessionEndedByUser {
		t.Fatalf("应为 session_ended_by_user, got %v", res.Reason)
	}

	// 重复结束：稳定、无副作用、可与正常结束区分
	res, out = sm.EndSession("alice", sid)
	t.Logf("重复结束 -> 判定: %+v outcome=%s", res, out)
	if out != EndOutcomeAlreadyEnded {
		t.Fatalf("重复结束应为 already_ended, got %s", out)
	}
	// 不存在的会话
	res, out = sm.EndSession("alice", "no-such-id")
	t.Logf("结束不存在的会话 -> 判定: %+v outcome=%s", res, out)
	if out != EndOutcomeNotFound {
		t.Fatalf("不存在应为 not_found, got %s", out)
	}
	// 他人的会话：按 not_found 处理，不改变状态
	sm.Issue("bob", "web")
	bobSID := sm.ListSessions("bob")[0].ID
	_, out = sm.EndSession("alice", bobSID)
	t.Logf("alice 结束 bob 的会话 -> outcome=%s", out)
	if out != EndOutcomeNotFound {
		t.Fatalf("他人会话应为 not_found, got %s", out)
	}
	if got := len(sm.ListSessions("bob")); got != 1 {
		t.Fatalf("bob 的会话不应被误伤, got %d", got)
	}
	// 已结束的会话不再出现在总览里
	if got := len(sm.ListSessions("alice")); got != 0 {
		t.Fatalf("结束后总览应为空, got %d", got)
	}
}

// 一键结束其他会话：保留当前会话，其余全部失效；重复调用返回 0。
func TestEndOtherSessions(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	cur := sm.Issue("alice", "web")
	old1 := sm.Issue("alice", "mobile")
	old2 := sm.Issue("alice", "desktop")

	keepID, ok := sm.FamilyIDOf(cur.AccessToken)
	if !ok {
		t.Fatal("应能定位当前访问令牌所属会话")
	}
	n := sm.EndOtherSessions("alice", keepID)
	t.Logf("输入: 保留当前会话 %s，一键结束其他 -> 结束 %d 个", keepID[:8], n)
	if n != 2 {
		t.Fatalf("应结束 2 个其他会话, got %d", n)
	}
	infos := sm.ListSessions("alice")
	if len(infos) != 1 || infos[0].ID != keepID {
		t.Fatalf("总览应只剩当前会话: %+v", infos)
	}
	// 被结束的会话令牌立即失效，原因为用户主动结束
	for i, p := range []TokenPair{old1, old2} {
		res, _ := sm.ValidateAccess(p.AccessToken)
		t.Logf("被结束会话 %d 的访问令牌 -> 判定: %+v", i, res)
		if res.Reason != ReasonSessionEndedByUser {
			t.Fatalf("应为 session_ended_by_user, got %v", res.Reason)
		}
	}
	// 当前会话不受影响
	res, _ := sm.ValidateAccess(cur.AccessToken)
	if !res.Allowed {
		t.Fatalf("当前会话应仍有效, got %v", res.Reason)
	}
	// 重复调用：稳定返回 0
	if n := sm.EndOtherSessions("alice", keepID); n != 0 {
		t.Fatalf("重复一键结束应返回 0, got %d", n)
	}
}

// 活动记录：建立/轮换/结束都能按账号查到，且带判定依据与配置快照。
func TestSessionEventsTrace(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	sm.SetMaxSessions(5)
	pair := sm.Issue("alice", "web")
	sid := sm.ListSessions("alice")[0].ID
	if res, _ := sm.Refresh(pair.RefreshToken); !res.Allowed {
		t.Fatalf("轮换应成功: %v", res.Reason)
	}
	sm.EndSession("alice", sid)

	// 记录生成后变更配置，历史快照不应被改写
	sm.SetMaxSessions(99)

	events := sm.Events("alice")
	for _, e := range events {
		t.Logf("事件 %s: 会话=%s 依据=%q 当时配置 maxSessions=%d accessTTL=%s refreshTTL=%s",
			e.Kind, e.FamilyID[:8], e.Detail, e.MaxSessions, e.AccessTTL, e.RefreshTTL)
	}
	if len(events) != 3 {
		t.Fatalf("应有 建立/轮换/结束 3 条记录, got %d", len(events))
	}
	want := []EventKind{EventIssued, EventRotated, EventEndedByUser}
	for i, k := range want {
		if events[i].Kind != k {
			t.Fatalf("事件 %d 应为 %s, got %s", i, k, events[i].Kind)
		}
		if events[i].MaxSessions != 5 || events[i].AccessTTL != time.Minute {
			t.Fatalf("事件 %d 应保留当时配置快照: %+v", i, events[i])
		}
	}
	if got := len(sm.Events("bob")); got != 0 {
		t.Fatalf("其他账号不应有记录, got %d", got)
	}
}
