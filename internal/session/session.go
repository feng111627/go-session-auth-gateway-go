package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DenyReason 会话阶段的可区分拒绝原因。
type DenyReason string

const (
	DenyTokenUnknown   DenyReason = "session_token_unknown"
	DenyTokenExpired   DenyReason = "session_token_expired"
	DenySessionRevoked DenyReason = "session_revoked"
	DenyRefreshReused  DenyReason = "refresh_token_reused"
)

// Error 携带结构化的会话拒绝原因。
type Error struct {
	Reason     DenyReason
	Detail     string
	FamilyID   string
	Suspicious bool
}

func (e *Error) Error() string {
	flag := ""
	if e.Suspicious {
		flag = " [family flagged suspicious and revoked]"
	}
	return string(e.Reason) + ": " + e.Detail + flag
}

// Meta 会话建立时的上下文。
type Meta struct {
	Username string
	Source   string
}

// TokenPair 一次签发或轮换得到的令牌对。
type TokenPair struct {
	SessionID        string    `json:"session_id"`
	FamilyID         string    `json:"family_id"`
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

// AccessInfo 访问令牌校验通过后得到的主体信息。
type AccessInfo struct {
	SessionID string
	FamilyID  string
	UserID    string
	Roles     []string
	Source    string
}

// FamilyInfo 刷新族状态，用于解释撤销/可疑标记。
type FamilyInfo struct {
	ID         string
	UserID     string
	Revoked    bool
	Suspicious bool
	RevokeAt   time.Time
	Sessions   []string
}

// session 是单个会话（一个刷新令牌链条）。
type session struct {
	id        string
	familyID  string
	userID    string
	roles     []string
	source    string
	createdAt time.Time
	revokedAt time.Time
}

func (s *session) revoked() bool { return !s.revokedAt.IsZero() }

// refreshRecord 记录一个刷新令牌的生命周期状态。
type refreshRecord struct {
	token      string
	familyID   string
	sessionID  string
	expiresAt  time.Time
	consumedAt time.Time // 零值表示尚未使用；非零表示已被正常轮换消费
	createdAt  time.Time
}

func (r *refreshRecord) consumed() bool { return !r.consumedAt.IsZero() }

// family 是同一次登录衍生出的会话族；检测到刷新令牌重放时整族撤销。
type family struct {
	id         string
	userID     string
	revokedAt  time.Time
	suspicious bool
	sessionIDs []string
}

func (f *family) revoked() bool { return !f.revokedAt.IsZero() }

// Manager 在进程内存中管理会话、令牌与刷新族。
type Manager struct {
	mu sync.Mutex

	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time
	seq        int

	sessions map[string]*session       // sessionID -> session
	families map[string]*family        // familyID -> family
	access   map[string]accessRecord   // access token -> session
	refresh  map[string]*refreshRecord // refresh token -> record
}

type accessRecord struct {
	sessionID string
	expiresAt time.Time
}

// NewManager 创建会话管理器。now 用于注入时钟，测试时可替换。
func NewManager(accessTTL, refreshTTL time.Duration, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		now:        now,
		sessions:   make(map[string]*session),
		families:   make(map[string]*family),
		access:     make(map[string]accessRecord),
		refresh:    make(map[string]*refreshRecord),
	}
}

func newToken(prefix string) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

// Issue 为认证主体建立新会话与新刷新族，并签发首个令牌对。
func (m *Manager) Issue(userID string, roles []string, meta Meta, t time.Time) (TokenPair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.seq++
	familyID := fmt.Sprintf("fam-%d-%d", m.seq, t.UnixNano())
	sessionID := fmt.Sprintf("ses-%d-%d", m.seq, t.UnixNano())

	fam := &family{id: familyID, userID: userID, sessionIDs: []string{sessionID}}
	sess := &session{
		id: sessionID, familyID: familyID, userID: userID,
		roles: append([]string(nil), roles...), source: meta.Source, createdAt: t,
	}
	m.families[familyID] = fam
	m.sessions[sessionID] = sess

	return m.mintLocked(sess, fam, t), nil
}

// mintLocked 必须在持有 m.mu 时调用：签发一组新令牌并登记。
func (m *Manager) mintLocked(sess *session, fam *family, t time.Time) TokenPair {
	accessToken := newToken("at")
	refreshToken := newToken("rt")
	accessExp := t.Add(m.accessTTL)
	refreshExp := t.Add(m.refreshTTL)

	m.access[accessToken] = accessRecord{sessionID: sess.id, expiresAt: accessExp}
	m.refresh[refreshToken] = &refreshRecord{
		token: refreshToken, familyID: fam.id, sessionID: sess.id,
		expiresAt: refreshExp, createdAt: t,
	}
	return TokenPair{
		SessionID: sess.id, FamilyID: fam.id,
		AccessToken: accessToken, RefreshToken: refreshToken,
		AccessExpiresAt: accessExp, RefreshExpiresAt: refreshExp,
	}
}

// VerifyAccess 校验访问令牌。
// 拒绝原因区分：未知令牌 -> session_token_unknown；
// 已过期 -> session_token_expired；所属会话/族已撤销 -> session_revoked。
func (m *Manager) VerifyAccess(token string, t time.Time) (AccessInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.access[token]
	if !ok {
		return AccessInfo{}, &Error{Reason: DenyTokenUnknown, Detail: "access token not recognized"}
	}
	sess := m.sessions[rec.sessionID]
	fam := m.families[sess.familyID]

	if fam.revoked() || sess.revoked() {
		when := sess.revokedAt
		if fam.revokedAt.Before(when) || when.IsZero() {
			when = fam.revokedAt
		}
		return AccessInfo{}, &Error{
			Reason: DenySessionRevoked, FamilyID: fam.id, Suspicious: fam.suspicious,
			Detail: fmt.Sprintf("session/family revoked at %s", when.Format(time.RFC3339Nano)),
		}
	}
	if !t.Before(rec.expiresAt) {
		return AccessInfo{}, &Error{
			Reason: DenyTokenExpired, FamilyID: fam.id,
			Detail: fmt.Sprintf("access token expired at %s", rec.expiresAt.Format(time.RFC3339Nano)),
		}
	}
	return AccessInfo{
		SessionID: sess.id, FamilyID: fam.id, UserID: sess.userID,
		Roles: append([]string(nil), sess.roles...), Source: sess.source,
	}, nil
}

// Refresh 消费一个刷新令牌并原子地轮换签发新令牌对。
//
// 并发安全保证：消费与重放检测在同一把锁内完成，因此多个请求并发使用同一个
// 刷新令牌时，恰好一个成功；其余请求要么看到“已消费”触发重放处置，要么直接失败，
// 不会有第二个请求被放行拿到新令牌。
//
// 重放处置：当一个“已经被正常轮换消费过”的刷新令牌再次出现时，视为被盗用，
// 立即撤销其所属的整个刷新族并标记 suspicious，本次不签发任何新令牌。
func (m *Manager) Refresh(token string, t time.Time) (TokenPair, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.refresh[token]
	if !ok {
		return TokenPair{}, &Error{Reason: DenyTokenUnknown, Detail: "refresh token not recognized"}
	}
	fam := m.families[rec.familyID]

	// 已消费过的令牌再次出现 = 重放攻击信号：整族撤销并标记可疑。
	if rec.consumed() {
		m.revokeFamilyLocked(fam, t, true)
		return TokenPair{}, &Error{
			Reason: DenyRefreshReused, FamilyID: fam.id, Suspicious: true,
			Detail: fmt.Sprintf("refresh token already consumed at %s; reuse detected", rec.consumedAt.Format(time.RFC3339Nano)),
		}
	}
	// 族已被撤销（例如先前的重放已触发）：不再发放新令牌。
	if fam.revoked() {
		return TokenPair{}, &Error{
			Reason: DenySessionRevoked, FamilyID: fam.id, Suspicious: fam.suspicious,
			Detail: "refresh family is revoked; no new tokens will be issued",
		}
	}
	if !t.Before(rec.expiresAt) {
		return TokenPair{}, &Error{
			Reason: DenyTokenExpired, FamilyID: fam.id,
			Detail: fmt.Sprintf("refresh token expired at %s", rec.expiresAt.Format(time.RFC3339Nano)),
		}
	}

	// 原子轮换：先消费旧令牌，再签发新令牌对（同一 session 延续同一条链条）。
	rec.consumedAt = t
	sess := m.sessions[rec.sessionID]
	pair := m.mintLocked(sess, fam, t)
	return pair, nil
}

// revokeFamilyLocked 必须在持有 m.mu 时调用。
func (m *Manager) revokeFamilyLocked(fam *family, t time.Time, suspicious bool) {
	if fam.revoked() {
		// 保留第一次撤销时的可疑标记；时间也不覆盖，便于解释“最初事件”。
		fam.suspicious = fam.suspicious || suspicious
		return
	}
	fam.revokedAt = t
	fam.suspicious = fam.suspicious || suspicious
	for _, sid := range fam.sessionIDs {
		if s, ok := m.sessions[sid]; ok && !s.revoked() {
			s.revokedAt = t
		}
	}
}

// RevokeSession 撤销指定会话：会话、其刷新族与所有未过期令牌立即失效。
func (m *Manager) RevokeSession(sessionID string, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sessionID]
	if !ok {
		return
	}
	if fam, ok := m.families[sess.familyID]; ok {
		m.revokeFamilyLocked(fam, t, false)
	}
}

// Family 查询刷新族状态（返回拷贝，避免外部修改内部状态）。
func (m *Manager) Family(familyID string) (FamilyInfo, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fam, ok := m.families[familyID]
	if !ok {
		return FamilyInfo{}, false
	}
	return FamilyInfo{
		ID: fam.id, UserID: fam.userID,
		Revoked: fam.revoked(), Suspicious: fam.suspicious,
		RevokeAt: fam.revokedAt, Sessions: append([]string(nil), fam.sessionIDs...),
	}, true
}
