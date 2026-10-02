package gateway

// Gateway 组合限流、认证、会话与授权，对外提供完整请求链路。
type Gateway struct {
	Limiter  *RateLimiter
	Auth     *Authenticator
	Sessions *SessionManager
	Authz    *Authorizer
}

// NewGateway 组装网关。
func NewGateway(l *RateLimiter, a *Authenticator, s *SessionManager, z *Authorizer) *Gateway {
	return &Gateway{Limiter: l, Auth: a, Sessions: s, Authz: z}
}

// Login 登录第一步：先按 账号+来源 限流，再校验密码并签发动态码。
func (g *Gateway) Login(account, source, password string) Result {
	if res := g.Limiter.Allow(account, source); !res.Allowed {
		return res
	}
	return g.Auth.Login(account, password)
}

// VerifyOTP 登录第二步：动态码通过后建立会话（记录登录入口 source）
// 并签发首对令牌。若账号活跃会话已达上限，最久未使用的旧会话会被自动回收。
func (g *Gateway) VerifyOTP(account, source, code string) (Result, TokenPair) {
	res, _ := g.Auth.VerifyOTP(account, code)
	if !res.Allowed {
		return res, TokenPair{}
	}
	return res, g.Sessions.IssueWithSource(account, source)
}

// Access 一次资源访问的完整链路：限流 -> 访问令牌校验 -> 授权判定。
// 任一环节拒绝都带可区分的原因；授权判定会被记录为历史；
// 令牌校验通过会更新会话的最近活动时间。
func (g *Gateway) Access(account, source, accessToken, resource, action, scene string) Decision {
	if res := g.Limiter.Allow(account, source); !res.Allowed {
		d := Decision{Result: res}
		return d
	}
	res, tokenAccount := g.Sessions.ValidateAccess(accessToken)
	if !res.Allowed {
		return Decision{Result: res}
	}
	_, roles := g.Auth.RolesOf(tokenAccount)
	return g.Authz.Authorize(roles, resource, action, scene)
}

// ListSessions 用户查看自己名下当前活跃会话的总览。
func (g *Gateway) ListSessions(account string) []SessionInfo {
	return g.Sessions.ListSessions(account)
}

// TerminateSession 用户主动结束自己名下的某个会话（幂等）。
// 被结束会话的访问/刷新令牌立即失效，拒绝原因为 session_terminated。
func (g *Gateway) TerminateSession(account, sessionID string) TerminateResult {
	return g.Sessions.TerminateSession(account, sessionID)
}

// TerminateOtherSessions 一键结束"除当前正在用的会话之外"的所有会话。
// 当前会话由用户出示的访问令牌定位；令牌无效时拒绝且不结束任何会话。
// 返回本次实际结束的会话 ID 列表。
func (g *Gateway) TerminateOtherSessions(account, accessToken string) (Result, []string) {
	res, tokenAccount := g.Sessions.ValidateAccess(accessToken)
	if !res.Allowed {
		return res, nil
	}
	if tokenAccount != account {
		return Reject(ReasonForbidden, "访问令牌不属于该账号，不能操作其会话"), nil
	}
	currentID, ok := g.Sessions.SessionIDOf(accessToken)
	if !ok {
		return Reject(ReasonTokenUnknown, "无法定位当前会话"), nil
	}
	return Allow("已结束除当前会话外的其他会话"),
		g.Sessions.TerminateOtherSessions(account, currentID)
}

// SessionEvents 查询账号名下的会话审计事件（建立/轮换/结束/回收/可疑）。
func (g *Gateway) SessionEvents(account string) []SessionEvent {
	return g.Sessions.Events(account)
}
