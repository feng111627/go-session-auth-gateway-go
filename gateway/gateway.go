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

// VerifyOTP 登录第二步：动态码通过后建立会话并签发首对令牌。
func (g *Gateway) VerifyOTP(account, code string) (Result, TokenPair) {
	res, _ := g.Auth.VerifyOTP(account, code)
	if !res.Allowed {
		return res, TokenPair{}
	}
	return res, g.Sessions.Issue(account)
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
