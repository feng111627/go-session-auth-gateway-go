package gateway

import (
	"testing"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/internal/authz"
)

// TestAccessDecisionReasons 覆盖访问判定的各条路径：
// 放行、越权、令牌过期、会话撤销、令牌未知，拒绝原因必须可区分。
func TestAccessDecisionReasons(t *testing.T) {
	env := newTestEnv(t)
	member := loginPair(t, env, "alice", "correct horse", "web")
	admin := loginPair(t, env, "root", "admin pass", "web")

	// 1) 普通成员访问自己有权限的 API -> allowed。
	d, err := env.gw.Access(AccessRequest{AccessToken: member.AccessToken, Account: "u-alice",
		Resource: "/api/widgets", Action: "GET", Scenario: authz.ScenarioAPI})
	if err != nil || !d.Allowed || d.Reason != authz.ReasonAllowed {
		t.Fatalf("member /api GET should be allowed, d=%+v err=%v", d, err)
	}
	t.Logf("decision %s: input(member,/api/widgets,GET,api) -> %s matched=%v policy=v%d",
		d.ID, d.Reason, d.MatchedRules, d.PolicyVersion)

	// 2) 普通成员访问管理资源 -> denied_by_policy（越权），命中显式 deny。
	d, err = env.gw.Access(AccessRequest{AccessToken: member.AccessToken, Account: "u-alice",
		Resource: "/admin/users", Action: "GET", Scenario: authz.ScenarioAdmin})
	if err != nil || d.Allowed || d.Reason != authz.ReasonDeniedByPolicy {
		t.Fatalf("member /admin should be denied_by_policy, d=%+v err=%v", d, err)
	}
	t.Logf("decision %s: input(member,/admin/users,GET,admin) -> %s matched=%v explanation=%q",
		d.ID, d.Reason, d.MatchedRules, d.Explanation)

	// 3) 管理员访问管理资源 -> allowed（对照组）。
	d, _ = env.gw.Access(AccessRequest{AccessToken: admin.AccessToken, Account: "u-admin",
		Resource: "/admin/users", Action: "GET", Scenario: authz.ScenarioAdmin})
	if !d.Allowed {
		t.Fatalf("admin /admin should be allowed, reason=%s matched=%v", d.Reason, d.MatchedRules)
	}
	t.Logf("decision %s: input(admin,/admin/users,GET,admin) -> %s matched=%v",
		d.ID, d.Reason, d.MatchedRules)

	// 4) 访问令牌过期 -> token_expired。
	env.step(11 * time.Minute) // access TTL = 10m
	d, err = env.gw.Access(AccessRequest{AccessToken: member.AccessToken, Account: "u-alice",
		Resource: "/api/widgets", Action: "GET", Scenario: authz.ScenarioAPI})
	if err != nil {
		t.Fatalf("expired token should produce a Decision, not error, got %v", err)
	}
	if d.Allowed || d.Reason != authz.ReasonTokenExpired {
		t.Fatalf("want token_expired, got allowed=%v reason=%s", d.Allowed, d.Reason)
	}
	t.Logf("decision %s: expired access token -> %s explanation=%q", d.ID, d.Reason, d.Explanation)
	env.step(-11 * time.Minute)

	// 5) 令牌未知 -> token_unknown。
	d, _ = env.gw.Access(AccessRequest{AccessToken: "at_does_not_exist", Account: "u-alice",
		Resource: "/api/widgets", Action: "GET", Scenario: authz.ScenarioAPI})
	if d.Allowed || d.Reason != authz.ReasonTokenUnknown {
		t.Fatalf("want token_unknown, got allowed=%v reason=%s", d.Allowed, d.Reason)
	}
	t.Logf("decision %s: unknown token -> %s", d.ID, d.Reason)

	// 6) 会话被主动撤销后 -> session_revoked。
	env.gw.sessions.RevokeSession(member.SessionID, env.now)
	d, _ = env.gw.Access(AccessRequest{AccessToken: member.AccessToken, Account: "u-alice",
		Resource: "/api/widgets", Action: "GET", Scenario: authz.ScenarioAPI})
	if d.Allowed || d.Reason != authz.ReasonSessionRevoked {
		t.Fatalf("want session_revoked, got allowed=%v reason=%s", d.Allowed, d.Reason)
	}
	t.Logf("decision %s: revoked session -> %s explanation=%q", d.ID, d.Reason, d.Explanation)
}

// TestHistoryExplainableAfterPolicyUpdate 策略更新后，历史判定仍保留旧版本快照，可解释。
func TestHistoryExplainableAfterPolicyUpdate(t *testing.T) {
	env := newTestEnv(t)
	member := loginPair(t, env, "alice", "correct horse", "web")

	// v1 下：member 不能访问 /admin -> denied_by_policy，命中显式 deny。
	d1, _ := env.gw.Access(AccessRequest{AccessToken: member.AccessToken, Account: "u-alice",
		Resource: "/admin/users", Action: "GET", Scenario: authz.ScenarioAdmin})
	id1 := d1.ID
	t.Logf("history decision %s under v%d: allowed=%v reason=%s matched=%v",
		id1, d1.PolicyVersion, d1.Allowed, d1.Reason, d1.MatchedRules)
	if d1.PolicyVersion != 1 || d1.Reason != authz.ReasonDeniedByPolicy {
		t.Fatalf("unexpected d1: %+v", d1)
	}

	// 更新到 v2：允许 member 访问 /admin/*（模拟策略变更）。
	env.gw.authz.UpdatePolicy(authz.Policy{
		Version: 2,
		Rules: []authz.Rule{
			{ID: "r-member-admin-v2", Role: "member", Resource: "/admin/*", Action: "*",
				Scenarios: []authz.Scenario{authz.ScenarioAdmin, authz.ScenarioAPI}, Effect: "allow"},
		},
	})
	d2, _ := env.gw.Access(AccessRequest{AccessToken: member.AccessToken, Account: "u-alice",
		Resource: "/admin/users", Action: "GET", Scenario: authz.ScenarioAdmin})
	t.Logf("fresh decision %s under v%d: allowed=%v reason=%s matched=%v",
		d2.ID, d2.PolicyVersion, d2.Allowed, d2.Reason, d2.MatchedRules)
	if d2.PolicyVersion != 2 || !d2.Allowed {
		t.Fatalf("under v2 member should be allowed, got %+v", d2)
	}

	// 旧判定凭 ID 取回：仍是 v1、仍是 denied，依据不被新策略改写。
	old, ok := env.gw.authz.Explain(id1)
	if !ok {
		t.Fatal("historical decision disappeared")
	}
	if old.PolicyVersion != 1 || old.Allowed || old.Reason != authz.ReasonDeniedByPolicy {
		t.Fatalf("historical decision mutated: %+v", old)
	}
	t.Logf("explain(%s) after update: policy_version=%d allowed=%v matched=%v explanation=%q (preserved)",
		old.ID, old.PolicyVersion, old.Allowed, old.MatchedRules, old.Explanation)
}
