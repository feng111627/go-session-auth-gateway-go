package gateway

import (
	"fmt"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/internal/authz"
	"github.com/feng111627/go-session-auth-gateway-go/internal/login"
	"github.com/feng111627/go-session-auth-gateway-go/internal/mfa"
	"github.com/feng111627/go-session-auth-gateway-go/internal/ratelimit"
	"github.com/feng111627/go-session-auth-gateway-go/internal/session"
	"github.com/feng111627/go-session-auth-gateway-go/internal/user"
)

// Gateway 编排登录、会话、限流与授权的门面。
type Gateway struct {
	users    *user.Store
	mfa      *mfa.Service
	login    *login.Service
	sessions *session.Manager
	limiter  *ratelimit.Limiter
	authz    *authz.Engine
	now      func() time.Time
}

// New 组装各组件。
func New(
	users *user.Store,
	mfaSvc *mfa.Service,
	loginSvc *login.Service,
	sessions *session.Manager,
	limiter *ratelimit.Limiter,
	engine *authz.Engine,
	now func() time.Time,
) *Gateway {
	if now == nil {
		now = time.Now
	}
	return &Gateway{
		users: users, mfa: mfaSvc, login: loginSvc,
		sessions: sessions, limiter: limiter, authz: engine, now: now,
	}
}

// LoginRequest 登录请求。
type LoginRequest struct {
	Username string
	Password string
	Code     string
	Source   string
}

// IssueMFACode 为本地演示签发当前动态码（生产环境不会有这个接口）。
func (g *Gateway) IssueMFACode(username string) (string, time.Time, error) {
	u, ok := g.users.FindByUsername(username)
	if !ok {
		return "", time.Time{}, &login.DenyError{Reason: login.DenyUserNotFound, Detail: "no such user: " + username}
	}
	code, exp := g.mfa.Issue(u.MFASecret, g.now())
	return code, exp, nil
}

// Login 执行完整登录（密码 + MFA + 锁定判定），成功后建立会话与刷新族。
func (g *Gateway) Login(req LoginRequest) (session.TokenPair, error) {
	t := g.now()
	res, err := g.login.Login(req.Username, req.Password, req.Code, t)
	if err != nil {
		return session.TokenPair{}, err // *login.DenyError，拒绝原因可断言
	}
	return g.sessions.Issue(res.UserID, res.Roles, session.Meta{
		Username: res.Username, Source: req.Source,
	}, t)
}

// Refresh 使用刷新令牌轮换；旧令牌重放会导致整族撤销并标记可疑。
func (g *Gateway) Refresh(refreshToken string) (session.TokenPair, error) {
	return g.sessions.Refresh(refreshToken, g.now())
}

// AccessRequest 携带令牌的资源访问请求。
type AccessRequest struct {
	AccessToken string
	Account     string // 可选：为空时使用令牌中的主体 ID 做账号维度限流
	Resource    string
	Action      string
	Scenario    authz.Scenario
}

// Access 做 限流 -> 访问令牌校验 -> 授权判定，返回不可变判定记录。
// 限流被拒时没有判定记录（返回错误，原因为 rate_limited_account/source）；
// 令牌未知/过期/撤销映射为 authz 中对应的状态原因；
// 其余进入策略匹配，allowed/denied_by_policy 均在 Decision 中体现。
func (g *Gateway) Access(req AccessRequest) (authz.Decision, error) {
	t := g.now()

	// 1. 访问令牌校验（先解析出主体，限流需要账号与来源）。
	info, err := g.sessions.VerifyAccess(req.AccessToken, t)
	status := authz.StatusActive
	if err != nil {
		se, ok := err.(*session.Error)
		if !ok {
			return authz.Decision{}, err
		}
		switch se.Reason {
		case session.DenyTokenUnknown:
			status = authz.StatusUnknown
		case session.DenyTokenExpired:
			status = authz.StatusExpired
		case session.DenySessionRevoked:
			status = authz.StatusRevoked
		default:
			return authz.Decision{}, se
		}
	}

	account := req.Account
	if account == "" {
		account = info.UserID
	}
	source := info.Source

	// 2. 限流（令牌无效也要计入限流，防止用无效令牌探测；其账号/来源退化为主键值）。
	if status != authz.StatusActive {
		account, source = fallbackKeys(req)
	}
	if v := g.limiter.Check(account, source, t); !v.Allowed {
		return authz.Decision{}, &RateLimitError{Verdict: v}
	}

	// 3. 授权判定（令牌异常时在引擎里直接以状态原因拒绝）。
	in := authz.Input{
		Subject:  info.UserID,
		Roles:    info.Roles,
		Resource: req.Resource,
		Action:   req.Action,
		Scenario: req.Scenario,
		Status:   status,
	}
	return g.authz.Authorize(in, t), nil
}

func fallbackKeys(req AccessRequest) (string, string) {
	acct := req.Account
	if acct == "" {
		acct = "unknown-account"
	}
	return acct, "unknown-source"
}

// RateLimitError 表示被限流拒绝，携带维度原因与重试间隔。
type RateLimitError struct {
	Verdict ratelimit.Verdict
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s: retry after %s", e.Verdict.Reason, e.Verdict.RetryAfter)
}

// Clock 返回网关当前使用的时钟函数（测试可借助 Clock/SetClock 控制时间）。
func (g *Gateway) Clock() func() time.Time { return g.now }

// SetClock 替换网关使用的时钟函数。
func (g *Gateway) SetClock(now func() time.Time) { g.now = now }
