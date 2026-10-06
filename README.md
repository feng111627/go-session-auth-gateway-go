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
  session.go        会话族、令牌轮换、重放检测、会话总览/结束/容量回收/活动记录（SessionManager）
  ratelimit.go      按 账号+来源 的固定窗口限流（RateLimiter）
  authz.go          角色+场景授权与判定历史（Authorizer）
  gateway.go        组合以上组件的完整请求链路（Gateway）
cmd/gateway/        本地演示程序
```

## 登录与多因素校验流程

1. `Gateway.Login(account, source, password)`：先过限流，再校验账号密码。
   密码通过后为该账号签发一个一次性动态码（本地模拟，用
   `OTPStore.LastCode` 取回，真实场景相当于短信下发）。
2. `Gateway.VerifyOTP(account, source, code)`：校验动态码，通过后建立会话族并
   签发首对令牌，`source` 记录登录入口（web/mobile/...），用于会话总览。

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

## 会话自助管理与集中结束

- `Gateway.ListSessions(account)`：会话总览，返回账号当前全部**活跃**会话，
  每项含登录入口（`Source`）、建立时间（`CreatedAt`）、最近一次使用时间
  （`LastActiveAt`，刷新轮换与访问资源都会刷新它）、可疑标记（`Suspicious`），
  按建立时间升序，结果稳定。
- `Gateway.EndSession(account, sessionID)`：结束名下某个会话。被结束会话的
  访问/刷新令牌**立即失效**，拒绝原因为 `session_ended_by_user`，与
  `session_evicted`（容量回收）、`session_revoked`（重放撤销）可区分。
  结束操作**幂等**，通过 `EndOutcome` 区分且不会出错：
  - `ended_now`：本次操作将会话结束；
  - `already_ended`：会话此前已结束（结果中带原终止方式），重复结束无副作用；
  - `not_found`：会话不存在或不属于该账号（不跨账号泄露存在性）。
- `Gateway.EndOtherSessions(account, currentAccessToken)`：一键结束除当前
  会话之外的全部会话。**先用当前访问令牌定位"当前会话"，凭证有问题就整体
  拒绝、一个会话都不结束**（返回结束数 0）：
  - 凭证缺失或不存在 → `token_unknown`；
  - 凭证已过期 → `token_expired`；
  - 凭证所属会话已结束/被回收 → 对应终止原因（如 `session_ended_by_user`）；
  - 凭证不属于该账号 → `forbidden`。
  凭证有效时只结束其余会话，当前正在使用的会话保持可用；重复调用稳定
  返回 0。校验与结束在同一把锁内完成，并发下结果自洽。

## 账号级会话容量与自动回收

- `SessionManager.SetMaxSessions(n)` 设置每账号活跃会话上限（0 表示不限），
  只影响之后的签发，不回溯回收存量会话。
- 登录使活跃会话数超上限时，按**最近最久未使用**规则回收旧会话，
  **本次刚建立的会话永远保留**，绝不会被当作回收对象——即使它与其他
  会话的时间戳相同。回收顺序稳定可预期：`LastActiveAt` 早者优先，
  并列时 `CreatedAt` 早者优先，再并列按会话 ID 字典序（确定性，
  与并发顺序、map 遍历顺序无关），事后可向用户解释"为什么清掉的是它"。
- 时间戳相同或并发登录不影响正确性：同一秒建立多个会话、或多个登录
  并发进来时，每次登录只保住自己刚建的会话，从其余会话中按上述顺序
  回收超额部分，活跃会话数始终不超过上限，仍有效的会话不会被误伤。
- 被回收会话的令牌立即失效，拒绝原因 `session_evicted`，与用户主动结束
  （`session_ended_by_user`）明确区分。
- **并发自洽**：签发、结束、刷新、回收全部在同一把互斥锁内完成。任意并发
  组合下，活跃会话数不超过上限，已失效会话不会被放行，存活会话不被误伤
  （有并发测试覆盖）。

## 会话活动记录与追溯

`Gateway.SessionEvents(account)` 按时间升序返回账号的会话活动记录，覆盖
关键动作：`issued`（建立）、`rotated`（轮换）、`ended_by_user`（主动结束）、
`evicted`（容量回收）、`marked_suspicious`（重放撤销）。每条记录含：

- `Detail`：当时的判定依据（如"超过上限 1，按最近最久未使用规则回收"）；
- **配置快照**：`MaxSessions` / `AccessTTL` / `RefreshTTL` 记录事件发生时的
  配置值。之后调整配置，历史记录仍按当时规则解释，不会对不上。

## 与旧行为的兼容范围

原有语义全部保留并有测试守护：正常轮换、宽限期内并发重复刷新只拒绝不撤销、
宽限期外重放撤销会话族并标记可疑、未知/过期/已撤销令牌原因可区分、登录与
动态码失败锁定、限流边界、授权判定历史。新增能力只是在原 `revoked` 语义上
细分了终止方式（`session_ended_by_user` / `session_evicted` / 原
`session_revoked`），不改变原有拒绝原因的判定路径。

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
# 全部单元测试（含验证码重放、会话并发刷新、限流边界、越权访问、
# 会话总览与集中结束、并发容量回收、结束后凭证失效、
# 同一时间戳/并发登录下新会话必存活、无效凭证一键结束整体拒绝）
go test ./... -v        # 日志中打印关键输入与判定依据

# 只跑本次修复的回归用例
go test ./gateway/ -v -run 'TestNewSessionSurvives|TestEvictionTieBreak|TestConcurrentLoginsAtSameTimestamp|TestEndOtherSessions'

# 并发竞态检查
go test -race ./...

# 端到端演示：登录 -> 多因素 -> 授权 -> 刷新 -> 重放检测
#            -> 会话总览/集中结束 -> 容量回收 -> 活动记录
go run ./cmd/gateway
```

测试用时钟可注入（`Clock`），过期、锁定到期、宽限期等时间相关行为
都用假时钟确定性验证。
