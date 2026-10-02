package gateway

import (
	"errors"
	"sync"
	"testing"

	"github.com/feng111627/go-session-auth-gateway-go/internal/session"
)

func sessionErr(t *testing.T, err error) *session.Error {
	t.Helper()
	var se *session.Error
	if !errors.As(err, &se) {
		t.Fatalf("expected *session.Error, got %T: %v", err, err)
	}
	return se
}

func mustLogin(t *testing.T, env *testEnv, user, pw string) (code string) {
	t.Helper()
	code, _, _ = env.gw.IssueMFACode(user)
	return code
}

// TestConcurrentRefreshExactlyOneSucceeds 多个请求并发使用同一个刷新令牌，
// 必须恰好成功一次，其余请求绝不能被错误放行拿到新令牌。
func TestConcurrentRefreshExactlyOneSucceeds(t *testing.T) {
	env := newTestEnv(t)
	code := mustLogin(t, env, "alice", "correct horse")
	pair, err := env.gw.Login(LoginRequest{Username: "alice", Password: "correct horse", Code: code, Source: "web"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	t.Logf("input: family=%s refresh_token=%s; firing %d concurrent refreshes",
		pair.FamilyID, pair.RefreshToken, 20)

	const n = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successTokens := map[string]bool{}
	var successCount, failCount int
	failReasons := map[session.DenyReason]int{}

	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			p, err := env.gw.Refresh(pair.RefreshToken)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
				successTokens[p.RefreshToken] = true
			} else {
				failCount++
				failReasons[sessionErr(t, err).Reason]++
			}
		}()
	}
	close(start)
	wg.Wait()

	t.Logf("decision: success=%d failure=%d fail_reasons=%v distinct_new_tokens=%d",
		successCount, failCount, failReasons, len(successTokens))

	if successCount != 1 {
		t.Fatalf("exactly one refresh must succeed, got %d (failures=%d)", successCount, failCount)
	}
	if failCount != n-1 {
		t.Fatalf("the other %d refreshes must fail, got %d failures", n-1, failCount)
	}
	if len(successTokens) != 1 {
		t.Fatalf("only one distinct new refresh token expected, got %d", len(successTokens))
	}
}

// TestRefreshReuseRevokesWholeFamily 旧刷新令牌被重复使用时：
// 本次拒绝 + 整个刷新族撤销并标记可疑 + 合法的新令牌也立即失效。
func TestRefreshReuseRevokesWholeFamily(t *testing.T) {
	env := newTestEnv(t)
	code := mustLogin(t, env, "root", "admin pass")
	first, err := env.gw.Login(LoginRequest{Username: "root", Password: "admin pass", Code: code, Source: "ops"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	oldRT := first.RefreshToken
	t.Logf("step1: initial family=%s old_rt=%s", first.FamilyID, oldRT)

	// 合法轮换一次。
	second, err := env.gw.Refresh(oldRT)
	if err != nil {
		t.Fatalf("legit rotation should succeed: %v", err)
	}
	t.Logf("step2: legit rotation new_rt=%s (old_rt now consumed)", second.RefreshToken)

	// 攻击者重放旧刷新令牌：必须拒绝并撤销整族。
	_, err = env.gw.Refresh(oldRT)
	se := sessionErr(t, err)
	if se.Reason != session.DenyRefreshReused || !se.Suspicious {
		t.Fatalf("want refresh_token_reused+suspicious, got reason=%s suspicious=%v", se.Reason, se.Suspicious)
	}
	t.Logf("step3: replay old_rt -> DENY reason=%s suspicious=%v family=%s", se.Reason, se.Suspicious, se.FamilyID)

	fam, ok := env.gw.sessions.Family(first.FamilyID)
	if !ok || !fam.Revoked || !fam.Suspicious {
		t.Fatalf("family must be revoked+suspicious, got %+v ok=%v", fam, ok)
	}
	t.Logf("step4: family state revoked=%v suspicious=%v revoke_at=%s",
		fam.Revoked, fam.Suspicious, fam.RevokeAt.Format("15:04:05.000"))

	// 合法轮换得到的新令牌也必须被拒绝（族已撤销），不会继续发放新令牌。
	_, err = env.gw.Refresh(second.RefreshToken)
	se2 := sessionErr(t, err)
	if se2.Reason != session.DenySessionRevoked {
		t.Fatalf("newest refresh token must be refused with session_revoked, got %s", se2.Reason)
	}
	t.Logf("step5: newest rt after family revoke -> DENY reason=%s (no new tokens issued)", se2.Reason)

	// 尚未过期的访问令牌同样立即失效。
	_, err = env.gw.sessions.VerifyAccess(second.AccessToken, env.now)
	if se3 := sessionErr(t, err); se3.Reason != session.DenySessionRevoked {
		t.Fatalf("access token should be session_revoked, got %v", err)
	}
}
