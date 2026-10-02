package gateway

import (
	"fmt"
	"sync"
	"time"
)

// User 是本地模拟的用户记录。
type User struct {
	Account  string
	Password string // 本地模拟，明文存储
	Roles    []string
}

// LoginConfig 登录与锁定策略配置。
type LoginConfig struct {
	MaxFailures  int           // 连续失败达到该次数即锁定
	LockDuration time.Duration // 锁定时长
}

// Authenticator 负责账号密码 + 多因素校验与失败锁定。
// 密码错误与动态码校验失败都计入连续失败次数；
// 锁定期间即使密码正确也拒绝；锁定到期自动恢复。
type Authenticator struct {
	mu      sync.Mutex
	cfg     LoginConfig
	otp     *OTPStore
	clock   Clock
	users   map[string]User
	failCnt map[string]int
	locked  map[string]time.Time // account -> 锁定截止时间
}

// NewAuthenticator 创建认证器。
func NewAuthenticator(users []User, otp *OTPStore, cfg LoginConfig, clock Clock) *Authenticator {
	if clock == nil {
		clock = realClock
	}
	a := &Authenticator{
		cfg: cfg, otp: otp, clock: clock,
		users: make(map[string]User), failCnt: make(map[string]int), locked: make(map[string]time.Time),
	}
	for _, u := range users {
		a.users[u.Account] = u
	}
	return a
}

// Login 登录第一步：校验账号与密码。通过后为该账号签发一次性动态码，
// 由 VerifyOTP 完成第二步。
func (a *Authenticator) Login(account, password string) Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	if until, ok := a.locked[account]; ok {
		if a.clock().Before(until) {
			return Reject(ReasonAccountLocked,
				fmt.Sprintf("账号已锁定至 %s，期间即使密码正确也不能通过", until.Format(time.RFC3339)))
		}
		// 锁定到期，自动恢复
		delete(a.locked, account)
		a.failCnt[account] = 0
	}
	u, ok := a.users[account]
	if !ok {
		return Reject(ReasonUnknownAccount, "账号不存在")
	}
	if u.Password != password {
		return a.recordFailure(account, "密码错误")
	}
	a.otp.Issue(account)
	return Allow("密码校验通过，已签发一次性动态码")
}

// VerifyOTP 登录第二步：校验动态码。全部通过则返回用户角色。
// 动态码校验失败同样计入连续失败次数。
func (a *Authenticator) VerifyOTP(account, code string) (Result, []string) {
	res := a.otp.Verify(account, code)
	if !res.Allowed {
		a.mu.Lock()
		defer a.mu.Unlock()
		if until, ok := a.locked[account]; ok && a.clock().Before(until) {
			return Reject(ReasonAccountLocked, "账号处于锁定中"), nil
		}
		// 只有真正的动态码校验失败才计入失败次数（无待校验码不计）
		if res.Reason != ReasonNoPendingOTP {
			failRes := a.recordFailure(account, res.Detail)
			failRes.Reason = res.Reason // 保留可区分的动态码拒绝原因
			return failRes, nil
		}
		return res, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failCnt[account] = 0 // 完整登录成功，清零失败计数
	u := a.users[account]
	return Allow("多因素校验通过，登录成功"), append([]string(nil), u.Roles...)
}

// recordFailure 记录一次失败，达到阈值则锁定。调用方须持有 a.mu。
func (a *Authenticator) recordFailure(account, why string) Result {
	a.failCnt[account]++
	n := a.failCnt[account]
	if n >= a.cfg.MaxFailures {
		a.locked[account] = a.clock().Add(a.cfg.LockDuration)
		a.failCnt[account] = 0
		return Reject(ReasonAccountLocked,
			fmt.Sprintf("连续失败 %d 次（%s），账号锁定 %s", n, why, a.cfg.LockDuration))
	}
	return Reject(ReasonBadPassword,
		fmt.Sprintf("%s（第 %d 次失败，%d 次后锁定）", why, n, a.cfg.MaxFailures))
}

// RolesOf 查询账号的角色（供授权环节使用）。
func (a *Authenticator) RolesOf(account string) (Result, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.users[account]
	if !ok {
		return Reject(ReasonUnknownAccount, "账号不存在"), nil
	}
	return Allow("ok"), append([]string(nil), u.Roles...)
}
