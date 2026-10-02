package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// TokenPair 一次签发/轮换得到的令牌对。
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time // 访问令牌过期时间
}

// sessionState 会话生命周期状态。
type sessionState string

const (
	stateActive     sessionState = "active"     // 活跃
	stateTerminated sessionState = "terminated" // 用户主动结束
	stateEvicted    sessionState = "evicted"    // 超容量被自动回收
	stateRevoked    sessionState = "revoked"    // 重放检测撤销
)

// rejectReasonLocked 把会话终态映射为可区分的拒绝原因。
func rejectReasonForState(s sessionState) RejectReason {
	switch s {
	case stateTerminated:
		return ReasonSessionTerminated
	case stateEvicted:
		return ReasonSessionEvicted
	default:
		return ReasonSessionRevoked
	}
}

// sessionFamily 一个会话族：一次登录建立，刷新时在其中轮换令牌。
type sessionFamily struct {
	id             string
	account        string
	source         string    // 登录入口（如 web、app）
	createdAt      time.Time // 会话建立时间
	lastActiveAt   time.Time // 最近一次被使用（建立/轮换/访问）的时间
	currentRefresh string
	prevRefresh    string    // 上一个被轮换掉的刷新令牌
	rotatedAt      time.Time // 最近一次轮换时间
	refreshExpires time.Time
	state          sessionState
	suspicious     bool
}

// accessRecord 访问令牌索引记录。
type accessRecord struct {
	familyID  string
	expiresAt time.Time
}

// SessionInfo 会话总览条目：用户看到的自己名下某个活跃会话。
type SessionInfo struct {
	ID           string
	Source       string    // 登录入口
	CreatedAt    time.Time // 建立时间
	LastActiveAt time.Time // 最近一次使用时间
	Suspicious   bool      // 是否被判定为可疑
}

// EventKind 会话审计事件类型。
type EventKind string

const (
	EventCreated    EventKind = "created"           // 会话建立
	EventRotated    EventKind = "rotated"           // 刷新令牌轮换
	EventTerminated EventKind = "terminated"        // 用户主动结束
	EventEvicted    EventKind = "evicted"           // 超容量自动回收
	EventSuspicious EventKind = "marked_suspicious" // 重放检测判为可疑并撤销
)

// SessionConfigSnapshot 事件发生时的会话配置快照，
// 配置调整后历史事件仍能按当时的规则解释。
type SessionConfigSnapshot struct {
	MaxSessionsPerAccount int
	AccessTTL             time.Duration
	RefreshTTL            time.Duration
	Leeway                time.Duration
}

// SessionEvent 一条会话审计事件：关键动作 + 判定依据 + 当时配置。
type SessionEvent struct {
	Time      time.Time
	Account   string
	SessionID string
	Kind      EventKind
	Detail    string // 做出该动作的判定依据
	Config    SessionConfigSnapshot
}

// TerminateStatus 结束会话的结果状态，三种结果稳定且可区分。
type TerminateStatus string

const (
	TerminateDone     TerminateStatus = "terminated"    // 本次操作成功结束
	TerminateAlready  TerminateStatus = "already_ended" // 会话此前已结束/回收/撤销
	TerminateNotFound TerminateStatus = "not_found"     // 会话不存在（或不属于该账号）
)

// TerminateResult 结束单个会话的结果。
type TerminateResult struct {
	Status TerminateStatus
	Detail string
}

// SessionManager 管理会话与令牌生命周期。
// 重放检测语义：使用"当前"刷新令牌 -> 正常轮换；
// 使用"上一个"令牌且在宽限期内（并发重复刷新）-> 拒绝但不撤销；
// 使用更旧的令牌或宽限期外的旧令牌 -> 撤销整个会话族并标记可疑。
// 容量语义：每个账号的活跃会话数不超过 maxSessions（<=0 表示不限），
// 超限建立新会话时按"最近活动时间最久未用"的规则回收旧会话。
// 所有判定与状态变更都在同一把互斥锁内完成，并发下最终状态自洽。
type SessionManager struct {
	mu           sync.Mutex
	accessTTL    time.Duration
	refreshTTL   time.Duration
	leeway       time.Duration // 并发重复刷新宽限期
	maxSessions  int           // 每账号活跃会话上限，<=0 不限
	clock        Clock
	families     map[string]*sessionFamily // familyID -> 会话族
	refreshIndex map[string]string         // 所有签发过的刷新令牌 -> familyID
	accessIndex  map[string]accessRecord   // 访问令牌 -> 记录
	events       []SessionEvent            // 审计事件（按发生顺序）
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

// SetMaxSessions 设置每账号活跃会话上限（<=0 表示不限）。
// 只影响之后的建立/回收判定，已记录的历史事件仍带当时快照。
func (m *SessionManager) SetMaxSessions(n int) { m.maxSessions = n }

// Issue 为账号建立新会话族并签发首对令牌（入口标记为 unknown）。
func (m *SessionManager) Issue(account string) TokenPair {
	return m.IssueWithSource(account, "unknown")
}

// IssueWithSource 为账号建立新会话族（记录登录入口）并签发首对令牌。
// 建立前若该账号活跃会话数已达上限，按"最久未使用"规则回收旧会话，
// 保证新会话一定存活且活跃总数不超过上限。
func (m *SessionManager) IssueWithSource(account, source string) TokenPair {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictForCapacityLocked(account, 1)
	now := m.clock()
	fam := &sessionFamily{
		id: newToken(), account: account, source: source,
		createdAt: now, lastActiveAt: now, state: stateActive,
	}
	m.families[fam.id] = fam
	m.logLocked(fam, EventCreated,
		fmt.Sprintf("账号 %s 从入口 %s 建立会话", account, source))
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
	if fam.state != stateActive {
		return Reject(rejectReasonForState(fam.state),
			fmt.Sprintf("会话 %s 已结束（状态=%s，可疑=%v）", fam.id, fam.state, fam.suspicious)), TokenPair{}
	}
	if refreshToken != fam.currentRefresh {
		// 旧令牌：宽限期内的"上一个"令牌视为并发重复刷新，拒绝但不撤销
		if refreshToken == fam.prevRefresh && m.clock().Before(fam.rotatedAt.Add(m.leeway)) {
			return Reject(ReasonRefreshReused,
				"旧刷新令牌在宽限期内被重复使用，判定为并发重复刷新，拒绝本次请求"), TokenPair{}
		}
		// 宽限期外的旧令牌重放：撤销整个会话族并标记可疑
		fam.state = stateRevoked
		fam.suspicious = true
		m.logLocked(fam, EventSuspicious,
			fmt.Sprintf("检测到旧刷新令牌重放（令牌非当前且超出宽限期 %s），会话族撤销并标记可疑", m.leeway))
		return Reject(ReasonRefreshReused,
			fmt.Sprintf("检测到旧刷新令牌重放，会话族 %s 已撤销并标记可疑", fam.id)), TokenPair{}
	}
	if !m.clock().Before(fam.refreshExpires) {
		return Reject(ReasonTokenExpired, "刷新令牌已过期，需要重新登录"), TokenPair{}
	}
	return Allow("刷新令牌轮换成功"), m.rotateLocked(fam)
}

// rotateLocked 轮换令牌对：旧刷新令牌作废（记入 prevRefresh），签发新令牌，
// 并更新最近活动时间、记录轮换事件。调用方须持有 m.mu。
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
	fam.lastActiveAt = now
	fam.refreshExpires = now.Add(m.refreshTTL)
	m.refreshIndex[pair.RefreshToken] = fam.id
	m.accessIndex[pair.AccessToken] = accessRecord{familyID: fam.id, expiresAt: pair.ExpiresAt}
	if fam.prevRefresh != "" { // 首次签发不记轮换事件（建立事件已记录）
		m.logLocked(fam, EventRotated,
			fmt.Sprintf("刷新令牌轮换成功，新刷新令牌有效期至 %s", fam.refreshExpires.Format(time.RFC3339)))
	}
	return pair
}

// ValidateAccess 校验访问令牌，区分未知、会话已结束（主动结束/自动回收/撤销）、
// 已过期。成功返回账号，并更新会话最近活动时间。
func (m *SessionManager) ValidateAccess(accessToken string) (Result, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.accessIndex[accessToken]
	if !ok {
		return Reject(ReasonTokenUnknown, "访问令牌不存在"), ""
	}
	fam := m.families[rec.familyID]
	if fam.state != stateActive {
		return Reject(rejectReasonForState(fam.state),
			fmt.Sprintf("会话 %s 已结束（状态=%s，可疑=%v）", fam.id, fam.state, fam.suspicious)), ""
	}
	if !m.clock().Before(rec.expiresAt) {
		return Reject(ReasonTokenExpired, "访问令牌已过期"), ""
	}
	fam.lastActiveAt = m.clock()
	return Allow("访问令牌有效"), fam.account
}

// ListSessions 返回账号名下当前活跃会话的总览（按建立时间升序，结果稳定）。
func (m *SessionManager) ListSessions(account string) []SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionInfo
	for _, fam := range m.families {
		if fam.account != account || fam.state != stateActive {
			continue
		}
		out = append(out, SessionInfo{
			ID: fam.id, Source: fam.source,
			CreatedAt: fam.createdAt, LastActiveAt: fam.lastActiveAt,
			Suspicious: fam.suspicious,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// TerminateSession 用户主动结束自己名下的某个会话。
// 幂等：重复结束、结束不存在/已结束的会话都返回稳定结果且不改乱状态；
// 会话属于其他账号时按 not_found 处理，不泄露他人会话的存在性。
func (m *SessionManager) TerminateSession(account, sessionID string) TerminateResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	fam, ok := m.families[sessionID]
	if !ok || fam.account != account {
		return TerminateResult{Status: TerminateNotFound,
			Detail: fmt.Sprintf("会话 %s 不存在或不属于账号 %s", sessionID, account)}
	}
	if fam.state != stateActive {
		return TerminateResult{Status: TerminateAlready,
			Detail: fmt.Sprintf("会话 %s 此前已结束（状态=%s），本次操作不改变状态", sessionID, fam.state)}
	}
	fam.state = stateTerminated
	m.logLocked(fam, EventTerminated, fmt.Sprintf("账号 %s 主动结束会话", account))
	return TerminateResult{Status: TerminateDone,
		Detail: fmt.Sprintf("会话 %s 已被账号 %s 主动结束", sessionID, account)}
}

// TerminateOtherSessions 结束账号名下除 keepSessionID 之外的全部活跃会话，
// 返回本次实际结束的会话 ID（按建立时间升序，结果稳定）。幂等：
// 已结束的会话不受影响也不会出现在返回列表中。
func (m *SessionManager) TerminateOtherSessions(account, keepSessionID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var victims []*sessionFamily
	for _, fam := range m.families {
		if fam.account == account && fam.state == stateActive && fam.id != keepSessionID {
			victims = append(victims, fam)
		}
	}
	sort.Slice(victims, func(i, j int) bool {
		if !victims[i].createdAt.Equal(victims[j].createdAt) {
			return victims[i].createdAt.Before(victims[j].createdAt)
		}
		return victims[i].id < victims[j].id
	})
	out := make([]string, 0, len(victims))
	for _, fam := range victims {
		fam.state = stateTerminated
		m.logLocked(fam, EventTerminated,
			fmt.Sprintf("账号 %s 一键结束除 %s 外的其他会话", account, keepSessionID))
		out = append(out, fam.id)
	}
	return out
}

// SessionIDOf 返回访问令牌所属的会话 ID，用于定位"当前正在用的会话"。
// 令牌不存在或会话已结束时返回 false。
func (m *SessionManager) SessionIDOf(accessToken string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.accessIndex[accessToken]
	if !ok {
		return "", false
	}
	fam := m.families[rec.familyID]
	if fam.state != stateActive {
		return "", false
	}
	return fam.id, true
}

// Events 返回账号名下的会话审计事件（只读副本，按发生顺序）。
// 每个事件都带发生时的配置快照，配置调整后历史仍可解释。
func (m *SessionManager) Events(account string) []SessionEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionEvent
	for _, e := range m.events {
		if e.Account == account {
			out = append(out, e)
		}
	}
	return out
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

// evictForCapacityLocked 为即将建立的 room 个新会话腾出席位：
// 若账号活跃会话数 + room 超过上限，按"最近活动时间最久未用"
// （并列时按建立时间、再按会话 ID，规则确定可解释）回收旧会话。
// 调用方须持有 m.mu。
func (m *SessionManager) evictForCapacityLocked(account string, room int) {
	if m.maxSessions <= 0 {
		return
	}
	var actives []*sessionFamily
	for _, fam := range m.families {
		if fam.account == account && fam.state == stateActive {
			actives = append(actives, fam)
		}
	}
	need := len(actives) + room - m.maxSessions
	if need <= 0 {
		return
	}
	sort.Slice(actives, func(i, j int) bool {
		if !actives[i].lastActiveAt.Equal(actives[j].lastActiveAt) {
			return actives[i].lastActiveAt.Before(actives[j].lastActiveAt)
		}
		if !actives[i].createdAt.Equal(actives[j].createdAt) {
			return actives[i].createdAt.Before(actives[j].createdAt)
		}
		return actives[i].id < actives[j].id
	})
	for i := 0; i < need && i < len(actives); i++ {
		fam := actives[i]
		fam.state = stateEvicted
		m.logLocked(fam, EventEvicted,
			fmt.Sprintf("账号活跃会话数达上限 %d，按最久未使用规则回收（最近活动 %s）",
				m.maxSessions, fam.lastActiveAt.Format(time.RFC3339)))
	}
}

// logLocked 追加一条审计事件，带当前配置快照。调用方须持有 m.mu。
func (m *SessionManager) logLocked(fam *sessionFamily, kind EventKind, detail string) {
	m.events = append(m.events, SessionEvent{
		Time: m.clock(), Account: fam.account, SessionID: fam.id,
		Kind: kind, Detail: detail,
		Config: SessionConfigSnapshot{
			MaxSessionsPerAccount: m.maxSessions,
			AccessTTL:             m.accessTTL,
			RefreshTTL:            m.refreshTTL,
			Leeway:                m.leeway,
		},
	})
}

// newToken 生成随机令牌字符串。
func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
