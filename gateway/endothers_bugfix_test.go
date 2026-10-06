package gateway

import (
	"testing"
	"time"
)

// 回归：一键结束其他会话时，定位"当前会话"的访问凭证有问题就必须整体拒绝，
// 一个会话都不结束（旧实现会把账号名下会话连当前正在用的一起踢掉）。
// 覆盖：凭证缺失 / 不存在 / 已过期 / 属于其他账号 / 所属会话已结束。
func TestEndOtherSessionsRejectsBadCredential(t *testing.T) {
	newGW := func(clock *fakeClock) *Gateway {
		return NewGateway(
			NewRateLimiter(100, time.Minute, clock.Now),
			nil,
			NewSessionManager(time.Minute, time.Hour, clock.Now),
			nil,
		)
	}

	t.Run("凭证缺失", func(t *testing.T) {
		clock := newFakeClock()
		g := newGW(clock)
		g.Sessions.Issue("alice", "web")
		g.Sessions.Issue("alice", "mobile")

		res, n := g.EndOtherSessions("alice", "")
		t.Logf("输入: 空访问令牌 -> 判定: %+v 结束数=%d", res, n)
		if res.Allowed || res.Reason != ReasonTokenUnknown || n != 0 {
			t.Fatalf("应拒绝(token_unknown)且结束 0 个, got %+v n=%d", res, n)
		}
		if got := len(g.ListSessions("alice")); got != 2 {
			t.Fatalf("一个会话都不应被结束, got %d", got)
		}
	})

	t.Run("凭证不存在", func(t *testing.T) {
		clock := newFakeClock()
		g := newGW(clock)
		g.Sessions.Issue("alice", "web")
		g.Sessions.Issue("alice", "mobile")

		res, n := g.EndOtherSessions("alice", "no-such-token")
		t.Logf("输入: 不存在的访问令牌 -> 判定: %+v 结束数=%d", res, n)
		if res.Allowed || res.Reason != ReasonTokenUnknown || n != 0 {
			t.Fatalf("应拒绝(token_unknown)且结束 0 个, got %+v n=%d", res, n)
		}
		if got := len(g.ListSessions("alice")); got != 2 {
			t.Fatalf("一个会话都不应被结束, got %d", got)
		}
	})

	t.Run("凭证已过期", func(t *testing.T) {
		clock := newFakeClock()
		g := newGW(clock)
		cur := g.Sessions.Issue("alice", "web")
		g.Sessions.Issue("alice", "mobile")
		clock.Advance(2 * time.Minute) // 超过访问令牌有效期 1 分钟

		res, n := g.EndOtherSessions("alice", cur.AccessToken)
		t.Logf("输入: 已过期的访问令牌 -> 判定: %+v 结束数=%d", res, n)
		if res.Allowed || res.Reason != ReasonTokenExpired || n != 0 {
			t.Fatalf("应拒绝(token_expired)且结束 0 个, got %+v n=%d", res, n)
		}
		if got := len(g.ListSessions("alice")); got != 2 {
			t.Fatalf("一个会话都不应被结束, got %d", got)
		}
	})

	t.Run("凭证属于其他账号", func(t *testing.T) {
		clock := newFakeClock()
		g := newGW(clock)
		bob := g.Sessions.Issue("bob", "web")
		g.Sessions.Issue("alice", "web")
		g.Sessions.Issue("alice", "mobile")

		res, n := g.EndOtherSessions("alice", bob.AccessToken)
		t.Logf("输入: 用 bob 的访问令牌操作 alice -> 判定: %+v 结束数=%d", res, n)
		if res.Allowed || res.Reason != ReasonForbidden || n != 0 {
			t.Fatalf("应拒绝(forbidden)且结束 0 个, got %+v n=%d", res, n)
		}
		if got := len(g.ListSessions("alice")); got != 2 {
			t.Fatalf("alice 的会话一个都不应被结束, got %d", got)
		}
		if got := len(g.ListSessions("bob")); got != 1 {
			t.Fatalf("bob 的会话不应被误伤, got %d", got)
		}
	})

	t.Run("凭证所属会话已结束", func(t *testing.T) {
		clock := newFakeClock()
		g := newGW(clock)
		cur := g.Sessions.Issue("alice", "web")
		g.Sessions.Issue("alice", "mobile")
		sid, _ := g.Sessions.FamilyIDOf(cur.AccessToken)
		g.Sessions.EndSession("alice", sid) // 先结束当前会话，再用它的令牌一键结束

		res, n := g.EndOtherSessions("alice", cur.AccessToken)
		t.Logf("输入: 已结束会话的访问令牌 -> 判定: %+v 结束数=%d", res, n)
		if res.Allowed || res.Reason != ReasonSessionEndedByUser || n != 0 {
			t.Fatalf("应拒绝(session_ended_by_user)且结束 0 个, got %+v n=%d", res, n)
		}
		if got := len(g.ListSessions("alice")); got != 1 {
			t.Fatalf("剩余的 mobile 会话不应被结束, got %d", got)
		}
	})
}

// 凭证有效时：只结束其余会话，当前正在使用的会话保持可用；
// 被结束会话的访问/刷新令牌立即失效且原因可区分；重复调用稳定返回 0。
func TestEndOtherSessionsWithValidToken(t *testing.T) {
	clock := newFakeClock()
	g := NewGateway(
		NewRateLimiter(100, time.Minute, clock.Now),
		nil,
		NewSessionManager(time.Minute, time.Hour, clock.Now),
		nil,
	)
	cur := g.Sessions.Issue("alice", "web")
	old1 := g.Sessions.Issue("alice", "mobile")
	old2 := g.Sessions.Issue("alice", "desktop")

	res, n := g.EndOtherSessions("alice", cur.AccessToken)
	t.Logf("输入: 当前会话(web)的有效访问令牌 -> 判定: %+v 结束数=%d", res, n)
	if !res.Allowed || n != 2 {
		t.Fatalf("应放行且结束 2 个其他会话, got %+v n=%d", res, n)
	}
	// 当前会话必须保持可用
	res, _ = g.Sessions.ValidateAccess(cur.AccessToken)
	t.Logf("当前会话访问令牌 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("当前会话必须保持可用, got %v", res.Reason)
	}
	// 被结束会话的访问与刷新令牌立即失效，原因可区分
	for i, p := range []TokenPair{old1, old2} {
		res, _ = g.Sessions.ValidateAccess(p.AccessToken)
		if res.Reason != ReasonSessionEndedByUser {
			t.Fatalf("被结束会话 %d 访问令牌应为 session_ended_by_user, got %v", i, res.Reason)
		}
		res, _ = g.Sessions.Refresh(p.RefreshToken)
		t.Logf("被结束会话 %d 刷新令牌 -> 判定: %+v", i, res)
		if res.Reason != ReasonSessionEndedByUser {
			t.Fatalf("被结束会话 %d 刷新令牌应为 session_ended_by_user, got %v", i, res.Reason)
		}
	}
	// 重复调用：稳定返回 0，当前会话仍可用
	res, n = g.EndOtherSessions("alice", cur.AccessToken)
	t.Logf("重复一键结束 -> 判定: %+v 结束数=%d", res, n)
	if !res.Allowed || n != 0 {
		t.Fatalf("重复调用应放行且结束 0 个, got %+v n=%d", res, n)
	}
	if res, _ := g.Sessions.ValidateAccess(cur.AccessToken); !res.Allowed {
		t.Fatalf("重复调用后当前会话仍应可用, got %v", res.Reason)
	}
}
