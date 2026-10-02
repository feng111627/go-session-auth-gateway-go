package gateway

import (
	"testing"
	"time"
)

func testRules() []PolicyRule {
	return []PolicyRule{
		{Role: "admin", Resource: "doc", Action: "write", Scene: "normal", Allow: true},
		{Role: "reader", Resource: "doc", Action: "read", Scene: "normal", Allow: true},
		{Role: "reader", Resource: "doc", Action: "write", Scene: "normal", Allow: false}, // 显式拒绝
	}
}

func TestAuthorizeAllowAndForbidden(t *testing.T) {
	az := NewAuthorizer(testRules())

	d := az.Authorize([]string{"reader"}, "doc", "read", "normal")
	t.Logf("reader 读 doc -> 判定: %+v 命中规则: %v", d.Result, d.MatchedRule)
	if !d.Allowed {
		t.Fatalf("reader 读应放行, got %v", d.Reason)
	}

	d = az.Authorize([]string{"reader"}, "doc", "write", "normal")
	t.Logf("reader 写 doc -> 判定: %+v 命中规则: %v (依据: 显式 DENY 规则)", d.Result, d.MatchedRule)
	if d.Reason != ReasonForbidden || d.MatchedRule == nil {
		t.Fatalf("显式拒绝应为 forbidden 且有命中规则, got %v", d.Reason)
	}

	d = az.Authorize([]string{"reader"}, "doc", "delete", "normal")
	t.Logf("reader 删 doc -> 判定: %+v 命中规则: %v (依据: 无规则命中，默认拒绝)", d.Result, d.MatchedRule)
	if d.Reason != ReasonForbidden || d.MatchedRule != nil {
		t.Fatalf("默认拒绝应为 forbidden 且无命中规则, got %v", d.Reason)
	}

	d = az.Authorize([]string{"admin"}, "doc", "write", "emergency")
	t.Logf("admin 在 emergency 场景写 doc -> 判定: %+v (依据: 场景不匹配)", d.Result)
	if d.Reason != ReasonForbidden {
		t.Fatalf("场景不匹配应拒绝, got %v", d.Reason)
	}
}

func TestPolicyUpdateKeepsHistoryExplainable(t *testing.T) {
	az := NewAuthorizer(testRules())

	before := az.Authorize([]string{"reader"}, "doc", "read", "normal")
	t.Logf("策略更新前判定: version=%d allowed=%v rule=%v", before.PolicyVersion, before.Allowed, before.MatchedRule)

	// 更新策略：撤销 reader 的读权限
	az.UpdatePolicy([]PolicyRule{
		{Role: "admin", Resource: "doc", Action: "write", Scene: "normal", Allow: true},
	})
	after := az.Authorize([]string{"reader"}, "doc", "read", "normal")
	t.Logf("策略更新后判定: version=%d allowed=%v reason=%v", after.PolicyVersion, after.Allowed, after.Reason)

	if before.PolicyVersion != 1 || !before.Allowed {
		t.Fatalf("历史判定应保留版本 1 且放行, got %+v", before)
	}
	if after.PolicyVersion != 2 || after.Allowed {
		t.Fatalf("新判定应为版本 2 且拒绝, got %+v", after)
	}
	history := az.Decisions()
	if len(history) != 2 {
		t.Fatalf("应有 2 条历史判定, got %d", len(history))
	}
	t.Logf("历史记录: [0]=%+v [1]=%+v", history[0], history[1])
	if history[0].PolicyVersion != 1 || history[1].PolicyVersion != 2 {
		t.Fatalf("历史判定版本应分别为 1 和 2")
	}
}

func TestGatewayAccessEndToEnd(t *testing.T) {
	clock := newFakeClock()
	users := []User{{Account: "alice", Password: "pw123", Roles: []string{"reader"}}}
	otp := NewOTPStore(30*time.Second, clock.Now)
	g := NewGateway(
		NewRateLimiter(10, time.Minute, clock.Now),
		NewAuthenticator(users, otp, LoginConfig{MaxFailures: 3, LockDuration: time.Minute}, clock.Now),
		NewSessionManager(time.Minute, time.Hour, clock.Now),
		NewAuthorizer(testRules()),
	)

	res := g.Login("alice", "web", "pw123")
	t.Logf("登录第一步 -> %+v", res)
	code := otp.records["alice"].Code
	res, pair := g.VerifyOTP("alice", code)
	t.Logf("登录第二步 -> %+v", res)
	if !res.Allowed {
		t.Fatalf("登录应成功, got %v", res.Reason)
	}

	d := g.Access("alice", "web", pair.AccessToken, "doc", "read", "normal")
	t.Logf("访问 doc:read -> %+v", d.Result)
	if !d.Allowed {
		t.Fatalf("应放行, got %v", d.Reason)
	}

	d = g.Access("alice", "web", pair.AccessToken, "doc", "write", "normal")
	t.Logf("越权访问 doc:write -> %+v (依据: 显式 DENY)", d.Result)
	if d.Reason != ReasonForbidden {
		t.Fatalf("越权应为 forbidden, got %v", d.Reason)
	}

	// 令牌过期与越权要能区分
	clock.Advance(61 * time.Second)
	d = g.Access("alice", "web", pair.AccessToken, "doc", "read", "normal")
	t.Logf("过期令牌访问 -> %+v", d.Result)
	if d.Reason != ReasonTokenExpired {
		t.Fatalf("过期应为 token_expired, got %v", d.Reason)
	}
}
