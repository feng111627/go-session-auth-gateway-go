package gateway

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// otpRecord 记录某个账号当前待校验的一次性动态码。
type otpRecord struct {
	Code      string
	ExpiresAt time.Time
	Used      bool
}

// OTPStore 管理一次性动态码的签发与校验，保证一个码只能用一次。
// 校验顺序：是否存在 -> 是否已用 -> 是否过期 -> 是否匹配，
// 以便把"已用重放"与"过期"、"错误"明确区分开。
type OTPStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	clock   Clock
	records map[string]*otpRecord // account -> 当前动态码
}

// NewOTPStore 创建动态码存储，ttl 为动态码有效期。
func NewOTPStore(ttl time.Duration, clock Clock) *OTPStore {
	if clock == nil {
		clock = realClock
	}
	return &OTPStore{ttl: ttl, clock: clock, records: make(map[string]*otpRecord)}
}

// Issue 为账号签发一个新的动态码并返回（本地模拟，直接明文返回）。
// 重复签发会覆盖旧码，旧码随后按"错误"处理。
func (s *OTPStore) Issue(account string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := randomCode()
	s.records[account] = &otpRecord{Code: code, ExpiresAt: s.clock().Add(s.ttl)}
	return code
}

// Verify 校验动态码，区分无待校验码、已使用、过期、错误四种情况。
// 无论成功与否，只要码匹配就会被标记为已用，保证不可重放。
func (s *OTPStore) Verify(account, code string) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[account]
	if !ok {
		return Reject(ReasonNoPendingOTP, "该账号没有待校验的动态码")
	}
	if rec.Used {
		return Reject(ReasonOTPReused, "动态码已被使用过，不允许重放")
	}
	if !s.clock().Before(rec.ExpiresAt) {
		return Reject(ReasonOTPExpired, "动态码已过期")
	}
	if rec.Code != code {
		return Reject(ReasonOTPInvalid, "动态码不匹配")
	}
	rec.Used = true // 一次性：匹配后立即作废
	return Allow("动态码校验通过")
}

// randomCode 生成 6 位数字动态码。
func randomCode() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	return fmt.Sprintf("%06d", n%1000000)
}

// LastCode 返回账号当前待校验的动态码。
// 仅用于本地模拟（真实场景中动态码会通过短信等渠道下发）。
func (s *OTPStore) LastCode(account string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.records[account]; ok {
		return rec.Code
	}
	return ""
}
