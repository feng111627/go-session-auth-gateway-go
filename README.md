# go-session-auth-gateway-go

本地可运行的登录认证与授权网关。用户、角色、策略全部用本地内存数据模拟，
不依赖任何外部服务或真实凭据。核心目标是：多因素登录、会话刷新、限流与
授权在并发下的判定结果**稳定且可解释**——每次拒绝都带可区分的原因
（`RejectReason`），每次授权判定都留下含策略版本与命中规则的历史记录。

## 结构

```
gateway/            核心库
  types.go          统一判定结果 Result 与可区分的拒绝原因 RejectReason
  otp.go            一次性动态码签发与校验（OTPStore）
  login.go          密码 + 多因素认证与失败锁定（Authenticator）
  session.go        会话族、令牌轮换与重放检测（SessionManager）
  ratelimit.go      按 账号+来源 的固定窗口限流（RateLimiter）
  authz.go          角色+场景授权与判定历史（Authorizer）
  gateway.go        组合以上组件的完整请求链路（Gateway）
cmd/gateway/        本地演示程序
```

## 登录与多因素校验流程

1. `Gateway.Login(account, source, password)`：先过限流，再校验账号密码。
   密码通过后为该账号签发一个一次性动态码（本地模拟，用
   `OTPStore.LastCode` 取回，真实场景相当于短信下发）。
2. `Gateway.VerifyOTP(account, code)`：校验动态码，通过后建立会话族并
   签发首对令牌。

动态码校验按 **是否存在 → 是否已用 → 是否过期 → 是否匹配** 的顺序判定，
拒绝原因可区分：

| 原因 | 含义 |
|---|---|
| `no_pending_otp` | 该账号没有待校验的动态码 |
| `otp_reused` | 动态码已被用过（重放） |
| `otp_expired` | 动态码已过期 |
| `otp_invalid` | 动态码不匹配 |

匹配成功的动态码立即作废，同一个码不可能用第二次。

**失败锁定**：密码错误与动态码校验失败都计入连续失败次数，达到
`LoginConfig.MaxFailures` 后锁定 `LockDuration`。锁定期间即使密码正确
也返回 `account_locked`；锁定到期后自动恢复，可正常登录。

## 会话轮换与撤销语义

- 访问令牌有明确有效期（`accessTTL`），过期返回 `token_expired`。
- 刷新令牌**使用时轮换**：每次 `Refresh` 成功后旧刷新令牌作废，签发新令牌对。
- **重放检测**：使用非当前刷新令牌时分两种情形——
  - 宽限期（默认 5s，可 `SetLeeway` 调整）内使用"上一个"令牌：判定为并发
    重复刷新，**拒绝本次请求但不撤销会话**；
  - 宽限期外或使用更旧的令牌：判定为重放攻击，**撤销整个会话族并标记可疑**
    （`IsSuspicious` 可查询），该族的所有刷新/访问令牌随即失效。
- **并发安全**：判定与轮换在同一把互斥锁内完成，N 个请求并发刷新同一会话
  时只有一个能成功，其余被拒绝，不会错误放行。

## 限流与授权规则

**限流**：按 `(账号, 来源)` 做固定窗口计数，每个窗口最多放行 `limit` 次，
超限返回 `rate_limited`。计数与窗口翻转在同一把锁内完成，并发下放行数
精确等于上限，不多放也不少放。窗口过期自动重置；不同来源独立计数。

**授权**：每次访问资源都调用 `Authorize(roles, resource, action, scene)`，
结合角色与使用场景判定：

- 命中 `Allow` 规则 → 放行；
- 命中显式 `Deny` 规则 → `forbidden`（记录命中规则）；
- 无规则命中 → 默认拒绝 `forbidden`（`MatchedRule` 为 nil，可与显式拒绝区分）。

每次判定都记录为不可变的 `Decision`（含策略版本号与命中规则快照）。
`UpdatePolicy` 整体替换策略并递增版本号，**历史判定仍带着做出它时的版本
与规则快照**，事后可以解释"当时为什么放行/拒绝"。

令牌层面的拒绝（`token_expired` / `session_revoked` / `token_unknown`）
与授权层面的拒绝（`forbidden`）使用不同的原因码，可明确区分。

## 本地验证

```bash
# 全部单元测试（含验证码重放、会话并发刷新、限流边界、越权访问）
go test ./... -v        # 日志中打印关键输入与判定依据

# 并发竞态检查
go test -race ./...

# 端到端演示：登录 -> 多因素 -> 授权 -> 刷新 -> 重放检测
go run ./cmd/gateway
```

测试用时钟可注入（`Clock`），过期、锁定到期、宽限期等时间相关行为
都用假时钟确定性验证。
