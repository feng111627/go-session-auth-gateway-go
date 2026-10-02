package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// TokenPair 一次签发/轮换得到的令牌对。
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time // 访问令牌过期时间
}

// sessionFamily 一个会话族：一次登录建立，刷新时在其中轮换令牌。
type sessionFamily struct {
	id             string
	account        string
	currentRefresh string
	prevRefresh    string    // 上一个被轮换掉的刷新令牌
	rotatedAt      time.Time // 最近一次轮换时间
	refreshExpires time.Time
	revoked        bool
	suspicious     bool
}

// accessRecord 访问令牌索引记录。
type accessRecord struct {
	familyID  string
	expiresAt time.Time
}

// SessionManager 管理会话与令牌生命周期。
// 重放检测语义：使用"当前"刷新令牌 -> 正常轮换；
// 使用"上一个"令牌且在宽限期内（并发重复刷新）-> 拒绝但不撤销；
// 使用更旧的令牌或宽限期外的旧令牌 -> 撤销整个会话族并标记可疑。
type SessionManager struct {
	mu           sync.Mutex
	accessTTL    time.Duration
	refreshTTL   time.Duration
	leeway       time.Duration // 并发重复刷新宽限期
	clock        Clock
	families     map[string]*sessionFamily // familyID -> 会话族
	refreshIndex map[string]string         // 所有签发过的刷新令牌 -> familyID
	accessIndex  map[string]accessRecord   // 访问令牌 -> 记录
}

// NewSessionManager 创建会话管理器。
func NewSessionManager(accessTTL, refreshTTL time.Duration, clock Clock) *SessionManager {
	if clock == nil {
		clock = realClock
	}
	return &SessionManager{
		accessTTL: accessTTL, refreshTTL: refreshTTL, leeway: 5 * time.Second, clock: clock,
		families:     make(map[string]*sessionFamily),
		refreshIndex: make(map[string]string),
		accessIndex:  make(map[string]accessRecord),
	}
}

// SetLeeway 调整并发重复刷新的宽限期（测试可用）。
func (m *SessionManager) SetLeeway(d time.Duration) { m.leeway = d }

// Issue 为账号建立新会话族并签发首对令牌。
func (m *SessionManager) Issue(account string) TokenPair {
	m.mu.Lock()
	defer m.mu.Unlock()
	fam := &sessionFamily{id: newToken(), account: account}
	m.families[fam.id] = fam
	return m.rotateLocked(fam)
}

// Refresh 用刷新令牌轮换新令牌对。整个判定与轮换在同一把锁内完成，
// 因此并发刷新同一会话时只有一个请求能轮换成功。
func (m *SessionManager) Refresh(refreshToken string) (Result, TokenPair) {
	m.mu.Lock()
	defer m.mu.Unlock()
	famID, ok := m.refreshIndex[refreshToken]
	if !ok {
		return Reject(ReasonTokenUnknown, "刷新令牌不存在"), TokenPair{}
	}
	fam := m.families[famID]
	if fam.revoked {
		return Reject(ReasonSessionRevoked,
			fmt.Sprintf("会话族 %s 已被撤销（可疑=%v）", fam.id, fam.suspicious)), TokenPair{}
	}
	if refreshToken != fam.currentRefresh {
		// 旧令牌：宽限期内的"上一个"令牌视为并发重复刷新，拒绝但不撤销
		if refreshToken == fam.prevRefresh && m.clock().Before(fam.rotatedAt.Add(m.leeway)) {
			return Reject(ReasonRefreshReused,
				"旧刷新令牌在宽限期内被重复使用，判定为并发重复刷新，拒绝本次请求"), TokenPair{}
		}
		// 宽限期外的旧令牌重放：撤销整个会话族并标记可疑
		fam.revoked = true
		fam.suspicious = true
		return Reject(ReasonRefreshReused,
			fmt.Sprintf("检测到旧刷新令牌重放，会话族 %s 已撤销并标记可疑", fam.id)), TokenPair{}
	}
	if !m.clock().Before(fam.refreshExpires) {
		return Reject(ReasonTokenExpired, "刷新令牌已过期，需要重新登录"), TokenPair{}
	}
	return Allow("刷新令牌轮换成功"), m.rotateLocked(fam)
}

// rotateLocked 轮换令牌对：旧刷新令牌作废（记入 prevRefresh），签发新令牌。
// 调用方须持有 m.mu。
func (m *SessionManager) rotateLocked(fam *sessionFamily) TokenPair {
	now := m.clock()
	pair := TokenPair{
		AccessToken:  newToken(),
		RefreshToken: newToken(),
		ExpiresAt:    now.Add(m.accessTTL),
	}
	fam.prevRefresh = fam.currentRefresh
	fam.currentRefresh = pair.RefreshToken
	fam.rotatedAt = now
	fam.refreshExpires = now.Add(m.refreshTTL)
	m.refreshIndex[pair.RefreshToken] = fam.id
	m.accessIndex[pair.AccessToken] = accessRecord{familyID: fam.id, expiresAt: pair.ExpiresAt}
	return pair
}

// ValidateAccess 校验访问令牌，区分未知、会话已撤销、已过期。成功返回账号。
func (m *SessionManager) ValidateAccess(accessToken string) (Result, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.accessIndex[accessToken]
	if !ok {
		return Reject(ReasonTokenUnknown, "访问令牌不存在"), ""
	}
	fam := m.families[rec.familyID]
	if fam.revoked {
		return Reject(ReasonSessionRevoked,
			fmt.Sprintf("会话族 %s 已被撤销（可疑=%v）", fam.id, fam.suspicious)), ""
	}
	if !m.clock().Before(rec.expiresAt) {
		return Reject(ReasonTokenExpired, "访问令牌已过期"), ""
	}
	return Allow("访问令牌有效"), fam.account
}

// IsSuspicious 查询某个刷新令牌所属会话族是否被标记为可疑（用于审计）。
func (m *SessionManager) IsSuspicious(refreshToken string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	famID, ok := m.refreshIndex[refreshToken]
	if !ok {
		return false
	}
	return m.families[famID].suspicious
}

// newToken 生成随机令牌字符串。
func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
