package gateway

import (
	"errors"
	"testing"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/internal/login"
)

func loginDenyReason(t *testing.T, err error) login.DenyReason {
	t.Helper()
	var de *login.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("expected *login.DenyError, got %T: %v", err, err)
	}
	return de.Reason
}

// TestMFACodeWrongExpiredReused 覆盖动态码的三种可区分拒绝原因。
func TestMFACodeWrongExpiredReused(t *testing.T) {
	env := newTestEnv(t)
	const user, pw = "alice", "correct horse"

	// --- 错误验证码：mfa_code_invalid ---
	_, exp, _ := env.gw.IssueMFACode(user)
	t.Logf("input: user=%s password=correct code=000000 (issued valid code expires=%s)", user, exp.Format(time.RFC3339Nano))
	_, err := env.gw.Login(LoginRequest{Username: user, Password: pw, Code: "000000", Source: "web"})
	if r := loginDenyReason(t, err); r != login.DenyMFAInvalid {
		t.Fatalf("want %s, got %s (%v)", login.DenyMFAInvalid, r, err)
	}
	t.Logf("decision: DENY reason=%s detail=%v", login.DenyMFAInvalid, err)

	// --- 正确验证码在过期后使用：mfa_code_expired ---
	code, exp, _ := env.gw.IssueMFACode(user)
	t.Logf("input: issued code=%s expires=%s; advancing clock past expiry", code, exp.Format(time.RFC3339Nano))
	env.step(3 * time.Minute) // TTL=2m
	_, err = env.gw.Login(LoginRequest{Username: user, Password: pw, Code: code, Source: "web"})
	if r := loginDenyReason(t, err); r != login.DenyMFAExpired {
		t.Fatalf("want %s, got %s (%v)", login.DenyMFAExpired, r, err)
	}
	t.Logf("decision: DENY reason=%s detail=%v", login.DenyMFAExpired, err)
	env.step(-3 * time.Minute) // 回到基线，后续用例不受影响

	// --- 同一验证码成功后重放：mfa_code_reused ---
	code, _, _ = env.gw.IssueMFACode(user)
	t.Logf("input: first login with code=%s (one-time)", code)
	pair, err := env.gw.Login(LoginRequest{Username: user, Password: pw, Code: code, Source: "web"})
	if err != nil {
		t.Fatalf("first login should succeed, got %v", err)
	}
	t.Logf("decision: ALLOW session=%s family=%s", pair.SessionID, pair.FamilyID)

	_, err = env.gw.Login(LoginRequest{Username: user, Password: pw, Code: code, Source: "web"})
	if r := loginDenyReason(t, err); r != login.DenyMFAReused {
		t.Fatalf("want %s, got %s (%v)", login.DenyMFAReused, r, err)
	}
	t.Logf("decision: DENY on replay reason=%s detail=%v", login.DenyMFAReused, err)
}

// TestAccountLockAndRecovery 覆盖连续失败锁定、锁定期正确密码也拒绝、到期恢复。
func TestAccountLockAndRecovery(t *testing.T) {
	env := newTestEnv(t)
	const user = "bob"

	// 连续 3 次错误密码 -> 第 3 次起账号锁定。
	for i := 1; i <= 2; i++ {
		_, err := env.gw.Login(LoginRequest{Username: user, Password: "wrong", Code: "x", Source: "web"})
		if r := loginDenyReason(t, err); r != login.DenyBadPassword {
			t.Fatalf("failure #%d want %s, got %s", i, login.DenyBadPassword, r)
		}
		t.Logf("failure #%d: reason=%s", i, login.DenyBadPassword)
	}
	_, err := env.gw.Login(LoginRequest{Username: user, Password: "wrong", Code: "x", Source: "web"})
	if r := loginDenyReason(t, err); r != login.DenyBadPassword {
		t.Fatalf("third failure itself still reports bad_password, got %s", r)
	}
	t.Logf("failure #3: reason=%s, account should now be locked", login.DenyBadPassword)

	// 锁定期间，即使密码正确也只能得到 account_locked。
	_, err = env.gw.Login(LoginRequest{Username: user, Password: "bob pw", Code: "anything", Source: "web"})
	if r := loginDenyReason(t, err); r != login.DenyLocked {
		t.Fatalf("want %s during lock window, got %s", login.DenyLocked, r)
	}
	t.Logf("decision while locked: reason=%s detail=%v", login.DenyLocked, err)

	// 到期后恢复：签发新码并正常登录。
	env.step(6 * time.Minute)
	code, _, _ := env.gw.IssueMFACode(user)
	pair, err := env.gw.Login(LoginRequest{Username: user, Password: "bob pw", Code: code, Source: "web"})
	if err != nil {
		t.Fatalf("login after lock expiry should succeed, got %v", err)
	}
	t.Logf("decision after recovery: ALLOW session=%s family=%s", pair.SessionID, pair.FamilyID)
}
