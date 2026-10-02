package gateway

import (
	"testing"
	"time"
)

func newTestAuth(clock *fakeClock) *Authenticator {
	users := []User{{Account: "alice", Password: "pw123", Roles: []string{"reader"}}}
	otp := NewOTPStore(30*time.Second, clock.Now)
	return NewAuthenticator(users, otp, LoginConfig{MaxFailures: 3, LockDuration: time.Minute}, clock.Now)
}

func TestOTPReusedRejected(t *testing.T) {
	clock := newFakeClock()
	auth := newTestAuth(clock)

	res := auth.Login("alice", "pw123")
	t.Logf("输入: 正确密码 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("密码正确应通过, got %v", res.Reason)
	}
	code := auth.otp.records["alice"].Code
	t.Logf("签发的动态码: %s", code)

	res, _ = auth.VerifyOTP("alice", code)
	t.Logf("第一次使用动态码 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("首次使用应通过, got %v", res.Reason)
	}

	res, _ = auth.VerifyOTP("alice", code)
	t.Logf("重放同一动态码 -> 判定: %+v (依据: 码已标记为已用)", res)
	if res.Allowed || res.Reason != ReasonOTPReused {
		t.Fatalf("重放应拒绝且原因为 otp_reused, got allowed=%v reason=%v", res.Allowed, res.Reason)
	}
}

func TestOTPInvalidAndExpired(t *testing.T) {
	clock := newFakeClock()
	auth := newTestAuth(clock)

	auth.Login("alice", "pw123")
	res, _ := auth.VerifyOTP("alice", "000000x")
	t.Logf("错误动态码 -> 判定: %+v", res)
	if res.Reason != ReasonOTPInvalid {
		t.Fatalf("错误码应为 otp_invalid, got %v", res.Reason)
	}

	// 重新登录签发新码，推进时钟使其过期
	auth2 := newTestAuth(clock)
	auth2.Login("alice", "pw123")
	code := auth2.otp.records["alice"].Code
	clock.Advance(31 * time.Second)
	res, _ = auth2.VerifyOTP("alice", code)
	t.Logf("过期动态码 -> 判定: %+v (依据: 签发后已过 31s > ttl 30s)", res)
	if res.Reason != ReasonOTPExpired {
		t.Fatalf("过期码应为 otp_expired, got %v", res.Reason)
	}
}

func TestLockoutAndRecovery(t *testing.T) {
	clock := newFakeClock()
	auth := newTestAuth(clock)

	// 连续 3 次密码错误触发锁定
	for i := 1; i <= 3; i++ {
		res := auth.Login("alice", "wrong")
		t.Logf("第 %d 次错误密码 -> 判定: %+v", i, res)
	}
	res := auth.Login("alice", "pw123")
	t.Logf("锁定期间输入正确密码 -> 判定: %+v (依据: 锁定未到期)", res)
	if res.Reason != ReasonAccountLocked {
		t.Fatalf("锁定期间应为 account_locked, got %v", res.Reason)
	}

	// 锁定到期后恢复正常
	clock.Advance(61 * time.Second)
	res = auth.Login("alice", "pw123")
	t.Logf("锁定到期后正确密码 -> 判定: %+v", res)
	if !res.Allowed {
		t.Fatalf("锁定到期后应恢复, got %v", res.Reason)
	}
}
