package mfa

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// Reason 用于区分动态码被拒绝的具体原因。
type Reason string

const (
	ReasonInvalid Reason = "mfa_code_invalid" // 验证码错误
	ReasonExpired Reason = "mfa_code_expired" // 验证码过期
	ReasonReused  Reason = "mfa_code_reused"  // 验证码已被使用
)

// Error 携带可断言的拒绝原因。
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Detail }

// codeEntry 是一个已签发验证码的完整生命周期状态。
type codeEntry struct {
	secret    string
	expiresAt time.Time
	used      bool
	usedAt    time.Time
}

func entryKey(secret, code string) string { return secret + "|" + code }

// Service 负责一次性动态码的签发与校验。
// 所有状态仅保存在进程内存中，属于本地模拟实现。
type Service struct {
	mu      sync.Mutex
	ttl     time.Duration
	codes   map[string]*codeEntry // key: secret|code
	counter int
}

// NewService 创建 MFA 服务，codeTTL 为每个动态码的有效期。
func NewService(codeTTL time.Duration) *Service {
	return &Service{
		ttl:   codeTTL,
		codes: make(map[string]*codeEntry),
	}
}

// Issue 为指定密钥签发一个 6 位数字动态码。
// 返回码内容与过期时刻；码内容同时被本地保存以供校验/重放追踪。
func (s *Service) Issue(secret string, t time.Time) (code string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.counter++
	// 以随机数生成 6 位码；冲突时重试（仅本地模拟，冲突概率极低）。
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if n < 0 {
			n = -n
		}
		newCode := fmt.Sprintf("%06d", n%1_000_000)
		key := entryKey(secret, newCode)
		if _, exists := s.codes[key]; exists {
			continue
		}
		expiresAt = t.Add(s.ttl)
		s.codes[key] = &codeEntry{secret: secret, expiresAt: expiresAt}
		return newCode, expiresAt
	}
}

// Verify 校验动态码。校验顺序：
//  1. 不存在 -> invalid；
//  2. 已使用 -> reused（重放是安全事件，优先于过期上报）；
//  3. 已过期 -> expired；
//  4. 通过并原子地标记为已使用，保证同一个码并发使用也只会成功一次。
func (s *Service) Verify(secret, code string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := entryKey(secret, code)
	e, ok := s.codes[key]
	if !ok || e.secret != secret {
		return &Error{Reason: ReasonInvalid, Detail: "code not found for the given secret"}
	}
	if e.used {
		return &Error{Reason: ReasonReused, Detail: fmt.Sprintf("code already used at %s", e.usedAt.Format(time.RFC3339Nano))}
	}
	if !t.Before(e.expiresAt) {
		return &Error{Reason: ReasonExpired, Detail: fmt.Sprintf("code expired at %s", e.expiresAt.Format(time.RFC3339Nano))}
	}

	e.used = true
	e.usedAt = t
	return nil
}
