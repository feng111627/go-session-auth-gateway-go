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

// VerifyOTP 登录第二步：动态码通过后建立会话并签发首对令牌，source 记录登录入口。
func (g *Gateway) VerifyOTP(account, source, code string) (Result, TokenPair) {
	res, _ := g.Auth.VerifyOTP(account, code)
	if !res.Allowed {
		return res, TokenPair{}
	}
	return res, g.Sessions.Issue(account, source)
}

// ListSessions 返回账号当前的全部活跃会话（会话总览）。
func (g *Gateway) ListSessions(account string) []SessionInfo {
	return g.Sessions.ListSessions(account)
}

// EndSession 用户主动结束名下某个会话，幂等且结果可区分。
func (g *Gateway) EndSession(account, sessionID string) (Result, EndOutcome) {
	return g.Sessions.EndSession(account, sessionID)
}

// EndOtherSessions 结束账号名下除当前访问令牌所属会话之外的全部会话。
// 访问令牌缺失、无效、过期或不属于该账号时直接拒绝，一个会话都不结束；
// 凭证有效时只结束其余会话，当前正在使用的会话保持可用。
func (g *Gateway) EndOtherSessions(account, currentAccessToken string) (Result, int) {
	return g.Sessions.EndOtherSessionsWithToken(account, currentAccessToken)
}

// SessionEvents 返回账号的会话活动记录（建立/轮换/结束/回收/可疑），
// 每条记录带判定依据与当时的配置快照。
func (g *Gateway) SessionEvents(account string) []SessionEvent {
	return g.Sessions.Events(account)
}

// Access 一次资源访问的完整链路：限流 -> 访问令牌校验 -> 授权判定。
// 任一环节拒绝都带可区分的原因；授权判定会被记录为历史。
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
