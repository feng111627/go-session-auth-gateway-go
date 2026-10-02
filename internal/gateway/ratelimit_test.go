package gateway

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/internal/authz"
	"github.com/feng111627/go-session-auth-gateway-go/internal/ratelimit"
	"github.com/feng111627/go-session-auth-gateway-go/internal/session"
)

func rateErr(t *testing.T, err error) *RateLimitError {
	t.Helper()
	var re *RateLimitError
	if !errors.As(err, &re) {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	return re
}

// loginPair 是测试辅助：完成一次登录并返回令牌对。
func loginPair(t *testing.T, env *testEnv, username, password, source string) session.TokenPair {
	t.Helper()
	code, _, _ := env.gw.IssueMFACode(username)
	pair, err := env.gw.Login(LoginRequest{
		Username: username, Password: password, Code: code, Source: source,
	})
	if err != nil {
		t.Fatalf("login %s: %v", username, err)
	}
	return pair
}

// TestRateLimitConcurrentBoundary 并发请求数恰好超过账号额度时，
// 放行数必须严格等于额度，且第 limit+1 个请求带 rate_limited_account 原因。
func TestRateLimitConcurrentBoundary(t *testing.T) {
	env := newTestEnv(t)
	pair := loginPair(t, env, "alice", "correct horse", "web")
	t.Logf("input: account limit=3/min, source limit=5/min; firing 8 concurrent requests for one account")

	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed, deniedAccount, deniedOther := 0, 0, 0

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := env.gw.Access(AccessRequest{
				AccessToken: pair.AccessToken, Account: "u-alice",
				Resource: "/api/widgets", Action: "GET", Scenario: authz.ScenarioAPI,
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				allowed++
			case isRateReason(err, ratelimit.ReasonAccountLimited):
				deniedAccount++
			default:
				deniedOther++
				t.Logf("unexpected denial: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	t.Logf("decision: allowed=%d denied_account=%d denied_other=%d", allowed, deniedAccount, deniedOther)
	if allowed != 3 || deniedAccount != 5 || deniedOther != 0 {
		t.Fatalf("want exactly 3 allowed / 5 rate_limited_account, got %d/%d/%d",
			allowed, deniedAccount, deniedOther)
	}
}

// TestRateLimitSourceDimensionAndWindowReset 验证来源维度独立计数，以及窗口滚动后恢复。
func TestRateLimitSourceDimensionAndWindowReset(t *testing.T) {
	env := newTestEnv(t)
	// 两个不同账号共享同一来源 NAT，账号额度 3 用不满，但来源额度 5 先触顶。
	pairA := loginPair(t, env, "alice", "correct horse", "shared-ip")
	pairB := loginPair(t, env, "bob", "bob pw", "shared-ip")

	allowed, deniedSource := 0, 0
	hit := func(pair session.TokenPair, account string) {
		_, err := env.gw.Access(AccessRequest{
			AccessToken: pair.AccessToken, Account: account,
			Resource: "/api/widgets", Action: "GET", Scenario: authz.ScenarioAPI,
		})
		if err == nil {
			allowed++
		} else if isRateReason(err, ratelimit.ReasonSourceLimited) {
			deniedSource++
		} else {
			t.Fatalf("unexpected: %v", err)
		}
	}

	// A 三次 + B 三次 = 6 次，来源上限 5 -> 5 放行 1 来源限流。
	for i := 0; i < 3; i++ {
		hit(pairA, "u-alice")
		hit(pairB, "u-bob")
	}
	t.Logf("input: 6 requests from shared source across 2 accounts -> allowed=%d source_limited=%d", allowed, deniedSource)
	if allowed != 5 || deniedSource != 1 {
		t.Fatalf("want 5 allowed / 1 rate_limited_source, got %d/%d", allowed, deniedSource)
	}

	// 窗口滚动 1 分钟后恢复。
	env.step(time.Minute + time.Second)
	allowed, deniedSource = 0, 0
	for i := 0; i < 3; i++ {
		hit(pairA, "u-alice")
	}
	t.Logf("after window reset: 3 more requests -> allowed=%d source_limited=%d", allowed, deniedSource)
	if allowed != 3 {
		t.Fatalf("want 3 allowed after reset, got allowed=%d limited=%d", allowed, deniedSource)
	}
}

// TestRateLimitRetryAfter 被拒结果必须带可解释的重试等待时间。
func TestRateLimitRetryAfter(t *testing.T) {
	env := newTestEnv(t)
	pair := loginPair(t, env, "alice", "correct horse", "web")
	req := AccessRequest{AccessToken: pair.AccessToken, Account: "u-alice",
		Resource: "/api/widgets", Action: "GET", Scenario: authz.ScenarioAPI}
	for i := 0; i < 3; i++ {
		if _, err := env.gw.Access(req); err != nil {
			t.Fatalf("request %d should pass: %v", i+1, err)
		}
	}
	_, err := env.gw.Access(req)
	re := rateErr(t, err)
	t.Logf("4th request: reason=%s retry_after=%s remaining=%d", re.Verdict.Reason, re.Verdict.RetryAfter, re.Verdict.Remaining)
	if re.Verdict.Reason != ratelimit.ReasonAccountLimited || re.Verdict.RetryAfter <= 0 {
		t.Fatalf("want account limit with positive retry-after, got %+v", re.Verdict)
	}
}

func isRateReason(err error, reason string) bool {
	var re *RateLimitError
	if errors.As(err, &re) {
		return re.Verdict.Reason == reason
	}
	return false
}
