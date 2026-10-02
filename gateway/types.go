// Package gateway 实现本地可运行的登录认证与授权网关。
// 用户、角色、策略均为本地内存数据，不依赖外部服务。
package gateway

import "time"

// RejectReason 表示一次判定被拒绝的原因，各类原因必须可区分。
type RejectReason string

const (
	// 登录与多因素相关
	ReasonUnknownAccount RejectReason = "unknown_account" // 账号不存在
	ReasonBadPassword    RejectReason = "bad_password"    // 密码错误
	ReasonOTPInvalid     RejectReason = "otp_invalid"     // 动态码错误
	ReasonOTPExpired     RejectReason = "otp_expired"     // 动态码过期
	ReasonOTPReused      RejectReason = "otp_reused"      // 动态码已被使用
	ReasonAccountLocked  RejectReason = "account_locked"  // 连续失败被锁定
	ReasonNoPendingOTP   RejectReason = "no_pending_otp"  // 没有待校验的动态码

	// 会话与令牌相关
	ReasonTokenExpired      RejectReason = "token_expired"      // 访问令牌过期
	ReasonTokenUnknown      RejectReason = "token_unknown"      // 令牌不存在
	ReasonSessionRevoked    RejectReason = "session_revoked"    // 会话族已被撤销（重放检测）
	ReasonRefreshReused     RejectReason = "refresh_reused"     // 旧刷新令牌被重放，会话族被撤销并标记可疑
	ReasonSessionTerminated RejectReason = "session_terminated" // 用户主动结束了该会话
	ReasonSessionEvicted    RejectReason = "session_evicted"    // 超出账号会话容量上限，被自动回收

	// 限流与授权相关
	ReasonRateLimited RejectReason = "rate_limited" // 触发限流
	ReasonForbidden   RejectReason = "forbidden"    // 角色/场景不允许
)

// Result 是一次判定的统一结果：要么放行，要么带原因拒绝。
type Result struct {
	Allowed bool
	Reason  RejectReason // Allowed 为 false 时有效
	Detail  string       // 可解释的补充说明
}

// Allow 构造放行结果。
func Allow(detail string) Result { return Result{Allowed: true, Detail: detail} }

// Reject 构造拒绝结果。
func Reject(r RejectReason, detail string) Result {
	return Result{Allowed: false, Reason: r, Detail: detail}
}

// Clock 返回当前时间，便于测试中注入假时钟。
type Clock func() time.Time

// realClock 默认时钟。
func realClock() time.Time { return time.Now() }
