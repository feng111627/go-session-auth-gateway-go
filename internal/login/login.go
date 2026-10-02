package login

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/internal/mfa"
	"github.com/feng111627/go-session-auth-gateway-go/internal/user"
)

// DenyReason 登录阶段的可区分拒绝原因。
type DenyReason string

const (
	DenyUserNotFound DenyReason = "user_not_found"
	DenyBadPassword  DenyReason = "bad_password"
	DenyLocked       DenyReason = "account_locked"
	DenyMFAInvalid   DenyReason = DenyReason(mfa.ReasonInvalid)
	DenyMFAExpired   DenyReason = DenyReason(mfa.ReasonExpired)
	DenyMFAReused    DenyReason = DenyReason(mfa.ReasonReused)
)

// DenyError 携带结构化的登录拒绝原因。
type DenyError struct {
	Reason      DenyReason
	Detail      string
	LockedUntil time.Time // 仅当账号当前处于锁定状态时有值
}

func (e *DenyError) Error() string { return string(e.Reason) + ": " + e.Detail }

// Config 锁定策略：连续失败 MaxFailures 次后锁定 LockDuration。
type Config struct {
	MaxFailures  int
	LockDuration time.Duration
}

// Result 登录成功后的认证主体信息。
type Result struct {
	UserID   string
	Username string
	Roles    []string
}

// lockState 是单个账号的连续失败计数与锁定到期时刻。
type lockState struct {
	failures    int
	lockedUntil time.Time
}

// Service 编排密码校验、MFA 校验与失败锁定。
type Service struct {
	mu    sync.Mutex
	users *user.Store
	mfa   *mfa.Service
	cfg   Config
	state map[string]*lockState
}

func NewService(users *user.Store, mfaSvc *mfa.Service, cfg Config) *Service {
	return &Service{users: users, mfa: mfaSvc, cfg: cfg, state: make(map[string]*lockState)}
}

// Login 在时刻 t 校验用户名、密码与一次性动态码。
//
// 判定顺序（每一步的拒绝原因互不相同，可被断言区分）：
//  1. 账号锁定中            -> account_locked（即使密码/MFA 全对也拒绝）；
//     锁定已到期则先恢复：清空计数后继续；
//  2. 账号不存在            -> user_not_found；
//  3. 密码错误              -> bad_password，并累计一次连续失败；
//  4. 动态码错误/过期/重放  -> mfa_code_invalid / mfa_code_expired /
//     mfa_code_reused，同样累计连续失败（重放是攻击信号）；
//  5. 连续失败达到阈值      -> 账号进入锁定，锁定状态可经 LockState 查询；
//  6. 全部通过              -> 清空计数并返回认证主体。
func (s *Service) Login(username, password, code string, t time.Time) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.state[username]
	if st == nil {
		st = &lockState{}
		s.state[username] = st
	}

	// 1. 锁定判定 / 到期恢复。
	if !st.lockedUntil.IsZero() {
		if t.Before(st.lockedUntil) {
			return Result{}, &DenyError{
				Reason:      DenyLocked,
				Detail:      fmt.Sprintf("account locked until %s due to %d consecutive failures", st.lockedUntil.Format(time.RFC3339Nano), st.failures),
				LockedUntil: st.lockedUntil,
			}
		}
		// 锁定到期：恢复正常，失败计数清零。
		st.failures = 0
		st.lockedUntil = time.Time{}
	}

	// 2. 用户查询。
	u, ok := s.users.FindByUsername(username)
	if !ok {
		return Result{}, &DenyError{Reason: DenyUserNotFound, Detail: "no such user: " + username}
	}

	// 3. 密码校验。
	if !user.VerifyPassword(u, password) {
		s.recordFailure(st, t)
		return Result{}, &DenyError{
			Reason:      DenyBadPassword,
			Detail:      fmt.Sprintf("password mismatch (consecutive failures=%d, locked_until=%s)", st.failures, fmtLockedUntil(st)),
			LockedUntil: st.lockedUntil,
		}
	}

	// 4. 一次性动态码校验（错误原因由 mfa.Service 区分）。
	if err := s.mfa.Verify(u.MFASecret, code, t); err != nil {
		var mfaErr *mfa.Error
		reason := DenyMFAInvalid
		detail := err.Error()
		if errors.As(err, &mfaErr) {
			reason = DenyReason(mfaErr.Reason)
			detail = mfaErr.Detail
		}
		s.recordFailure(st, t)
		return Result{}, &DenyError{
			Reason:      reason,
			Detail:      fmt.Sprintf("%s (consecutive failures=%d, locked_until=%s)", detail, st.failures, fmtLockedUntil(st)),
			LockedUntil: st.lockedUntil,
		}
	}

	// 5. 成功：清空失败状态。
	st.failures = 0
	st.lockedUntil = time.Time{}
	return Result{UserID: u.ID, Username: u.Username, Roles: u.Roles}, nil
}

// recordFailure 必须在持有 s.mu 的前提下调用。
func (s *Service) recordFailure(st *lockState, t time.Time) {
	st.failures++
	if st.failures >= s.cfg.MaxFailures {
		st.lockedUntil = t.Add(s.cfg.LockDuration)
	}
}

func fmtLockedUntil(st *lockState) string {
	if st.lockedUntil.IsZero() {
		return "-"
	}
	return st.lockedUntil.Format(time.RFC3339Nano)
}

// LockState 返回账号在时刻 t 是否处于锁定状态及锁定到期时刻。
func (s *Service) LockState(username string, t time.Time) (locked bool, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[username]
	if st == nil || st.lockedUntil.IsZero() {
		return false, time.Time{}
	}
	if t.Before(st.lockedUntil) {
		return true, st.lockedUntil
	}
	return false, time.Time{}
}
