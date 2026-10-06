package gateway

import (
	"testing"
	"time"
)

// 一键结束其他会话：定位"当前会话"的访问凭证有问题时，必须直接拒绝且
// 一个会话都不结束（包括当前正在用的）。覆盖：缺失/不存在/过期/他人凭证/
// 已结束会话的凭证。
func TestEndOtherSessionsRejectsInvalidCurrentToken(t *testing.T) {
	newGateway := func(clock *fakeClock) (*Gateway, *SessionManager) {
		sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
		return NewGateway(nil, nil, sm, nil), sm
	}

	// 每个用例都先建 3 个会话，再用有问题的凭证一键结束，
	// 判定依据：拒绝 + 返回 0 + 3 个会话全部仍然活跃。
	cases := []struct {
		name   string
		reason RejectReason
		token  func(cur, other TokenPair, sm *SessionManager) string
	}{
		{"凭证缺失(空串)", ReasonTokenUnknown, func(cur, other TokenPair, sm *SessionManager) string { return "" }},
		{"凭证不存在", ReasonTokenUnknown, func(cur, other TokenPair, sm *SessionManager) string { return "no-such-token" }},
		{"凭证属于其他账号", ReasonForbidden, func(cur, other TokenPair, sm *SessionManager) string { return other.AccessToken }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock()
			g, sm := newGateway(clock)
			cur := sm.Issue("alice", "web")
			sm.Issue("alice", "mobile")
			sm.Issue("alice", "desktop")
			bob := sm.Issue("bob", "web")

			tok := tc.token(cur, bob, sm)
			res, n := g.EndOtherSessions("alice", tok)
			t.Logf("输入: 当前凭证=%q(%s) -> 判定: %+v 结束数=%d", tok, tc.name, res, n)
			if res.Allowed || res.Reason != tc.reason {
				t.Fatalf("应拒绝(%s), got %+v", tc.reason, res)
			}
			if n != 0 {
				t.Fatalf("凭证无效时一个会话都不该结束, got %d", n)
			}
			if got := len(sm.ListSessions("alice")); got != 3 {
				t.Fatalf("alice 的 3 个会话都应保持活跃, got %d", got)
			}
			if got := len(sm.ListSessions("bob")); got != 1 {
				t.Fatalf("bob 的会话不应受影响, got %d", got)
			}
			// 当前会话凭证必须仍可用（用户不被踢下线）
			if res, _ := sm.ValidateAccess(cur.AccessToken); !res.Allowed {
				t.Fatalf("当前会话被误伤: %+v", res)
			}
		})
	}

	// 过期凭证：时钟推进超过访问令牌有效期
	t.Run("凭证已过期", func(t *testing.T) {
		clock := newFakeClock()
		g, sm := newGateway(clock)
		cur := sm.Issue("alice", "web")
		sm.Issue("alice", "mobile")
		clock.Advance(2 * time.Minute) // 超过 accessTTL=1min

		res, n := g.EndOtherSessions("alice", cur.AccessToken)
		t.Logf("输入: 过期访问凭证 -> 判定: %+v 结束数=%d", res, n)
		if res.Allowed || res.Reason != ReasonTokenExpired {
			t.Fatalf("应拒绝(token_expired), got %+v", res)
		}
		if n != 0 || len(sm.ListSessions("alice")) != 2 {
			t.Fatalf("过期凭证不应结束任何会话: n=%d 活跃=%d", n, len(sm.ListSessions("alice")))
		}
	})

	// 已结束会话的凭证：会话已被用户结束，其凭证不能再用来定位"当前会话"
	t.Run("凭证所属会话已结束", func(t *testing.T) {
		clock := newFakeClock()
		g, sm := newGateway(clock)
		cur := sm.Issue("alice", "web")
		sm.Issue("alice", "mobile")
		sid := sm.ListSessions("alice")[0].ID
		sm.EndSession("alice", sid) // 结束 web 会话

		res, n := g.EndOtherSessions("alice", cur.AccessToken)
		t.Logf("输入: 已结束会话的访问凭证 -> 判定: %+v 结束数=%d", res, n)
		if res.Allowed || res.Reason != ReasonSessionEndedByUser {
			t.Fatalf("应拒绝(session_ended_by_user), got %+v", res)
		}
		if n != 0 || len(sm.ListSessions("alice")) != 1 {
			t.Fatalf("不应再结束任何会话: n=%d 活跃=%d", n, len(sm.ListSessions("alice")))
		}
	})
}

// 一键结束其他会话：凭证有效时只结束其余会话，当前会话保持可用；
// 重复调用稳定返回 0。
func TestEndOtherSessionsWithValidToken(t *testing.T) {
	clock := newFakeClock()
	sm := NewSessionManager(time.Minute, time.Hour, clock.Now)
	g := NewGateway(nil, nil, sm, nil)

	cur := sm.Issue("alice", "web")
	old1 := sm.Issue("alice", "mobile")
	old2 := sm.Issue("alice", "desktop")

	res, n := g.EndOtherSessions("alice", cur.AccessToken)
	t.Logf("输入: 有效当前凭证 -> 判定: %+v 结束数=%d", res, n)
	if !res.Allowed || n != 2 {
		t.Fatalf("应放行并结束 2 个其他会话, got %+v n=%d", res, n)
	}
	// 当前会话保持可用
	if res, _ := sm.ValidateAccess(cur.AccessToken); !res.Allowed {
		t.Fatalf("当前会话必须保持可用: %+v", res)
	}
	// 其余会话的访问/刷新凭证立即失效，原因可区分
	for i, p := range []TokenPair{old1, old2} {
		if res, _ := sm.ValidateAccess(p.AccessToken); res.Reason != ReasonSessionEndedByUser {
			t.Fatalf("被结束会话 %d 的访问凭证应为 session_ended_by_user, got %+v", i, res)
		}
		if res, _ := sm.Refresh(p.RefreshToken); res.Reason != ReasonSessionEndedByUser {
			t.Fatalf("被结束会话 %d 的刷新凭证应为 session_ended_by_user, got %+v", i, res)
		}
	}
	t.Logf("判定: 其余 2 个会话的访问/刷新凭证均以 session_ended_by_user 拒绝，当前会话正常")

	// 重复调用：稳定返回 0，当前会话仍可用
	res, n = g.EndOtherSessions("alice", cur.AccessToken)
	t.Logf("重复一键结束 -> 判定: %+v 结束数=%d", res, n)
	if !res.Allowed || n != 0 {
		t.Fatalf("重复调用应放行且结束 0 个, got %+v n=%d", res, n)
	}
	if res, _ := sm.ValidateAccess(cur.AccessToken); !res.Allowed {
		t.Fatalf("重复调用后当前会话仍应可用: %+v", res)
	}
}
