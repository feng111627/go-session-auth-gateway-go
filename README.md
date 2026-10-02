# go-session-auth-gateway（本地模拟版）

一套可在本地独立运行的登录认证与授权网关。**用户、角色、策略、验证码、会话、计数全部保存在进程内存中模拟**，不连接数据库、不调用外部 MFA 服务、不使用任何真实凭据（密码用确定性的 `fake$` 前缀“哈希”模拟）。

设计重点不是功能堆砌，而是让以下行为在**并发**下结果稳定、且每一次拒绝都有**可区分、可断言、可回溯**的原因：

- 账号密码 + 一次性动态码（MFA）多因素登录；
- 连续失败锁定与到期恢复；
- 访问令牌有效期、刷新令牌轮换、重放检测与会话族撤销；
- 按账号/来源双维度限流；
- 角色 × 使用场景的授权判定，以及历史判定的可解释性。

## 目录结构

```
internal/user       内存用户/角色存储，模拟密码校验
internal/mfa        一次性动态码签发/校验（错误/过期/重放三态区分）
internal/login      密码+MFA 编排、连续失败计数与锁定
internal/session    访问/刷新令牌、轮换、重放检测、会话族撤销
internal/ratelimit  账号+来源双维度固定窗口限流
internal/authz      角色×场景策略判定、deny 优先、历史判定快照
internal/gateway    对外门面，编排以上全部组件
cmd/demo            本地 HTTP 演示服务
```

## 一、登录与多因素校验流程

`login.Service.Login(username, password, code, t)` 的判定顺序固定，每一步的拒绝原因互不相同：

| 顺序 | 判定 | 拒绝原因（常量） |
|----|------|------|
| 1 | 账号锁定中（即使密码/MFA 全对也拒绝） | `account_locked` |
| 2 | 用户不存在 | `user_not_found` |
| 3 | 密码错误 | `bad_password` |
| 4 | 动态码错误（不存在/不匹配） | `mfa_code_invalid` |
| 4 | 动态码已过期 | `mfa_code_expired` |
| 4 | 动态码已被使用（重放） | `mfa_code_reused` |
| 5 | 全部通过 | 建立会话 |

MFA 细节：

- 动态码为 6 位数字，默认 TTL 2 分钟，一次性使用；
- 校验在互斥锁内完成“查状态 → 判定 → 标记已使用”，因此**同一个码并发提交也只有第一次能通过**；
- 上报优先级为 **重放 > 过期 > 错误**：一个用过且恰好也过期的码，再次出现仍按重放（安全事件）处理。

锁定与恢复（默认 `MaxFailures=3`，`LockDuration=5m`）：

- 密码错误或 MFA 失败（含重放）都累计一次连续失败；
- 达到阈值后账号进入锁定，响应里带 `locked_until`；
- **锁定期间即使凭据全部正确也只能得到 `account_locked`**；
- 锁定到期后下一次请求自动清零计数、恢复正常，无需人工解锁。

## 二、会话轮换与撤销语义

登录成功后签发一对令牌：

- **访问令牌**（`at_…`，默认 10 分钟有效）：用于访问资源，短期、自包含校验；
- **刷新令牌**（`rt_…`，默认 30 分钟有效）：一次性使用，用一次即轮换出新的一对。

关键安全语义：

1. **刷新令牌轮换**：每次 `Refresh` 原子地“消费旧 rt → 签发新 at/rt”。旧 rt 立即失效。
2. **并发刷新只成功一次**：消费动作与重放检查在同一把锁内，因此 N 个请求并发使用同一个 rt 时**恰好 1 个拿到新令牌**，其余全部拒绝（原因 `refresh_token_reused`），不会出现多放行。
3. **重放即整族撤销**：一旦一个“已消费”的 rt 再次出现，判定为令牌被盗用：
   - 本次拒绝，错误带 `refresh_token_reused` 且 `suspicious=true`；
   - 立即撤销其所属的整个**刷新族**（同一次登录衍生的会话/令牌链）并标记可疑；
   - 合法轮换链路上最新的 rt 再使用会得到 `session_revoked`，未过期的 at 也立即失效；
   - 不会继续发放任何新令牌。
4. **原因区分**：`session_token_unknown` / `session_token_expired` / `session_revoked` / `refresh_token_reused` 四类互不混淆，测试可直接断言。

## 三、限流规则

`ratelimit.Limiter` 对每次访问在两个维度各计 1 次（默认固定窗口 1 分钟）：

- 账号维度：3 次/分钟（`rate_limited_account`）
- 来源维度：5 次/分钟（`rate_limited_source`）

实现要点：

- 两个窗口**先一起预检，都有余量才在同一临界区同时递增**；任一维度超限则拒绝，且**被拒绝的请求不消耗任何额度**；
- 账号维度优先上报，拒绝原因稳定；
- 因此并发突发下每个维度都**恰好放行前 limit 个**，不多不少（有并发测试与 `-race` 验证）；
- 被拒响应带 `RetryAfter`（距窗口重置时间）；窗口滚动后自动恢复。

## 四、授权规则与可解释性

访问资源时网关依次执行：**访问令牌校验 → 限流 → 授权判定**。

- 令牌状态非有效时不进入策略匹配，直接给出对应原因：`token_unknown` / `token_expired` / `session_revoked`，与“越权”明确区分；
- 策略匹配采用 **deny 优先**：
  - 命中任意显式 `deny` → `denied_by_policy`；
  - 否则命中至少一条 `allow` → `allowed`；
  - 没有任何命中 → `denied_by_policy`（越权）；
- 规则按 `角色 + 资源(支持 `/admin/*` 通配) + 动作 + 使用场景(api/admin)` 匹配。

可解释性：

- 每次判定生成不可变的 `Decision`（唯一 ID、输入快照、`policy_version`、命中规则 ID、文字解释）；
- 策略可以随时 `UpdatePolicy`（版本号递增），但**历史判定永久保留当时的策略版本与依据**；
- 用 `Engine.Explain(decisionID)` 可在策略更新后依旧解释“当初为什么这样判”。

## 五、本地验证

### 跑单元测试（含关键输入与判定依据日志）

```bash
go test ./... -count=1 -v
# 并发安全验证
go test ./... -race -count=1
```

重点用例：

| 测试 | 覆盖场景 |
|------|---------|
| `TestMFACodeWrongExpiredReused` | 动态码错误/过期/重放三态可区分 |
| `TestAccountLockAndRecovery` | 连续失败锁定、锁定期拒绝、到期恢复 |
| `TestConcurrentRefreshExactlyOneSucceeds` | 20 个并发刷新恰好 1 个成功 |
| `TestRefreshReuseRevokesWholeFamily` | 旧 rt 重放 → 整族撤销 + 可疑 + 新令牌失效 |
| `TestRateLimitConcurrentBoundary` | 8 并发 / 额度 3，恰好 3 放行 5 拒绝 |
| `TestRateLimitSourceDimensionAndWindowReset` | 来源维度独立计数、窗口恢复 |
| `TestAccessDecisionReasons` | allowed/越权/过期/撤销/未知原因区分 |
| `TestHistoryExplainableAfterPolicyUpdate` | 策略升级后历史判定仍按旧版本可解释 |

### 跑 HTTP 演示

```bash
go run ./cmd/demo
# 监听 :8080，预置账号：alice / correct horse（member），root / admin pass（admin）
```

```bash
# 1) 本地演示专用：取当前一次性动态码
curl -s -X POST localhost:8080/demo/mfa-code -d '{"username":"alice"}'

# 2) 登录（把上一步 code 填入）
curl -s -X POST localhost:8080/login \
  -d '{"username":"alice","password":"correct horse","code":"123456","source":"web"}'

# 3) 访问资源（member 访问 /api 放行，访问 /admin 被 deny）
curl -s -X POST localhost:8080/access \
  -d '{"access_token":"<at>","account":"u-alice","resource":"/api/widgets","action":"GET","scenario":"api"}'

# 4) 刷新轮换
curl -s -X POST localhost:8080/refresh -d '{"refresh_token":"<rt>"}'
# 再用一次同一个旧 rt -> refresh_token_reused，整族撤销并标记 suspicious

# 5) 查看历史判定
curl -s localhost:8080/decisions
```

连续输错 3 次密码可观察到 `account_locked`（5 分钟）；连续请求超过限流阈值可观察到 `rate_limited_account/source` 与 `retry_after`。

## 说明

本项目为本地模拟演示：令牌为随机字符串、密码为模拟哈希、数据不持久化、无网络外部依赖。所有时间都通过可注入的时钟获取，测试中可精确推进到“过期之后/锁定到期之后/窗口滚动之后”等边界时刻。
