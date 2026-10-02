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

// EndKind 会话终止方式，用于区分"用户主动结束 / 容量回收 / 重放撤销"。
type EndKind string

const (
	EndActive  EndKind = ""               // 会话仍活跃
	EndByUser  EndKind = "ended_by_user"  // 用户主动结束
	EndEvicted EndKind = "evicted"        // 账号容量超限被自动回收
	EndReplay  EndKind = "revoked_replay" // 刷新令牌重放检测撤销
)

// EndOutcome 结束会话操作的结果，重复结束与正常结束可区分且稳定。
type EndOutcome string

const (
	EndOutcomeEnded        EndOutcome = "ended_now"     // 本次操作将会话结束
	EndOutcomeAlreadyEnded EndOutcome = "already_ended" // 会话此前已结束，本次无副作用
	EndOutcomeNotFound     EndOutcome = "not_found"     // 会话不存在（或不属于该账号）
)

// EventKind 会话活动事件类型。
type EventKind string

const (
	EventIssued           EventKind = "issued"            // 登录建立会话
	EventRotated          EventKind = "rotated"           // 刷新轮换令牌
	EventEndedByUser      EventKind = "ended_by_user"     // 用户主动结束
	EventEvicted          EventKind = "evicted"           // 容量超限自动回收
	EventMarkedSuspicious EventKind = "marked_suspicious" // 重放检测撤销并标记可疑
)

// SessionEvent 一条会话活动记录。MaxSessions/AccessTTL/RefreshTTL 是事件
// 发生时的配置快照：之后配置变更，历史记录仍按当时规则解释。
type SessionEvent struct {
	Time        time.Time
	Account     string
	FamilyID    string
	Kind        EventKind
	Detail      string        // 判定依据说明
	MaxSessions int           // 当时的账号会话容量上限（0 表示不限）
	AccessTTL   time.Duration // 当时的访问令牌有效期
	RefreshTTL  time.Duration // 当时的刷新令牌有效期
}

// SessionInfo 会话总览中的一项（仅活跃会话）。
type SessionInfo struct {
	ID           string
	Account      string
	Source       string    // 登录入口
	CreatedAt    time.Time // 建立时间
	LastActiveAt time.Time // 最近一次使用时间
	Suspicious   bool      // 是否被判定可疑
}

// sessionFamily 一个会话族：一次登录建立，刷新时在其中轮换令牌。
type sessionFamily struct {
	id             string
	account        string
	source         string    // 登录入口
	createdAt      time.Time // 建立时间
	lastActiveAt   time.Time // 最近一次使用时间（刷新或访问）
	currentRefresh string
	prevRefresh    string    // 上一个被轮换掉的刷新令牌
	rotatedAt      time.Time // 最近一次轮换时间
	refreshExpires time.Time
	revoked        bool // 不再放行（结束/回收/重放撤销均置位）
	suspicious     bool
	endKind        EndKind // 终止方式；revoked 为 true 时有效
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
// 容量语义：同一账号活跃会话数超过 maxSessions 时，按"最近最久未使用"
// （lastActiveAt 最小者优先，并列时建立早者优先）回收旧会话。
type SessionManager struct {
	mu           sync.Mutex
	accessTTL    time.Duration
	refreshTTL   time.Duration
	leeway       time.Duration // 并发重复刷新宽限期
	maxSessions  int           // 每账号活跃会话上限，0 表示不限
	clock        Clock
	families     map[string]*sessionFamily // familyID -> 会话族
	refreshIndex map[string]string         // 所有签发过的刷新令牌 -> familyID
	accessIndex  map[string]accessRecord   // 访问令牌 -> 记录
	events       []SessionEvent            // 全量活动记录（按时间追加）
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

// SetMaxSessions 设置每账号活跃会话上限（0 表示不限）。只影响之后的签发，
// 不回溯回收已存在的会话；历史事件里保留了当时的上限快照。
func (m *SessionManager) SetMaxSessions(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxSessions = n
}

// Issue 为账号建立新会话族并签发首对令牌，source 记录登录入口。
// 建立后按容量规则回收该账号最久未使用的旧会话。
func (m *SessionManager) Issue(account, source string) TokenPair {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock()
	fam := &sessionFamily{
		id: newToken(), account: account, source: source,
		createdAt: now, lastActiveAt: now,
	}
	m.families[fam.id] = fam
	pair := m.rotateLocked(fam)
	m.recordLocked(fam, EventIssued,
		fmt.Sprintf("账号 %s 从入口 %q 登录建立会话", account, source))
	m.enforceCapacityLocked(account)
	return pair
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
		return m.rejectForFamilyLocked(fam), TokenPair{}
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
		fam.endKind = EndReplay
		m.recordLocked(fam, EventMarkedSuspicious,
			"检测到宽限期外的旧刷新令牌重放，撤销会话族并标记可疑")
		return Reject(ReasonRefreshReused,
			fmt.Sprintf("检测到旧刷新令牌重放，会话族 %s 已撤销并标记可疑", fam.id)), TokenPair{}
	}
	if !m.clock().Before(fam.refreshExpires) {
		return Reject(ReasonTokenExpired, "刷新令牌已过期，需要重新登录"), TokenPair{}
	}
	pair := m.rotateLocked(fam)
	m.recordLocked(fam, EventRotated, "刷新令牌轮换成功，签发新令牌对")
	return Allow("刷新令牌轮换成功"), pair
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
	fam.lastActiveAt = now
	fam.refreshExpires = now.Add(m.refreshTTL)
	m.refreshIndex[pair.RefreshToken] = fam.id
	m.accessIndex[pair.AccessToken] = accessRecord{familyID: fam.id, expiresAt: pair.ExpiresAt}
	return pair
}

// ValidateAccess 校验访问令牌，区分未知、会话已结束/回收/撤销、已过期。
// 成功返回账号，并更新会话最近活动时间。
func (m *SessionManager) ValidateAccess(accessToken string) (Result, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.accessIndex[accessToken]
	if !ok {
		return Reject(ReasonTokenUnknown, "访问令牌不存在"), ""
	}
	fam := m.families[rec.familyID]
	if fam.revoked {
		return m.rejectForFamilyLocked(fam), ""
	}
	if !m.clock().Before(rec.expiresAt) {
		return Reject(ReasonTokenExpired, "访问令牌已过期"), ""
	}
	fam.lastActiveAt = m.clock()
	return Allow("访问令牌有效"), fam.account
}

// rejectForFamilyLocked 按终止方式给出可区分的拒绝原因。调用方须持有 m.mu。
func (m *SessionManager) rejectForFamilyLocked(fam *sessionFamily) Result {
	switch fam.endKind {
	case EndByUser:
		return Reject(ReasonSessionEndedByUser,
			fmt.Sprintf("会话 %s 已被用户主动结束，其令牌不再放行", fam.id))
	case EndEvicted:
		return Reject(ReasonSessionEvicted,
			fmt.Sprintf("会话 %s 因账号会话数超限被自动回收，其令牌不再放行", fam.id))
	default:
		return Reject(ReasonSessionRevoked,
			fmt.Sprintf("会话族 %s 已被撤销（可疑=%v）", fam.id, fam.suspicious))
	}
}

// ListSessions 返回账号当前的全部活跃会话，按建立时间升序，结果稳定。
func (m *SessionManager) ListSessions(account string) []SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []SessionInfo
	for _, fam := range m.families {
		if fam.account != account || fam.revoked {
			continue
		}
		out = append(out, SessionInfo{
			ID: fam.id, Account: fam.account, Source: fam.source,
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

// EndSession 用户主动结束名下某个会话。幂等：
//   - 会话存在且活跃 -> 结束并返回 EndOutcomeEnded；
//   - 会话已结束 -> 返回 EndOutcomeAlreadyEnded，状态不再改变；
//   - 会话不存在或不属于该账号 -> 返回 EndOutcomeNotFound。
//
// 三种情况都不产生错误，结果稳定且互相可区分。
func (m *SessionManager) EndSession(account, familyID string) (Result, EndOutcome) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fam, ok := m.families[familyID]
	if !ok || fam.account != account {
		return Allow(fmt.Sprintf("会话 %s 不存在，无需结束（幂等，无副作用）", familyID)),
			EndOutcomeNotFound
	}
	if fam.revoked {
		return Allow(fmt.Sprintf("会话 %s 此前已结束（方式=%s），重复结束无副作用", fam.id, fam.endKind)),
			EndOutcomeAlreadyEnded
	}
	fam.revoked = true
	fam.endKind = EndByUser
	m.recordLocked(fam, EventEndedByUser, "用户主动结束会话，其全部令牌立即失效")
	return Allow(fmt.Sprintf("会话 %s 已结束，名下令牌立即失效", fam.id)), EndOutcomeEnded
}

// EndOtherSessions 结束账号名下除 keepFamilyID 之外的全部活跃会话，
// 返回本次实际结束的会话数。重复调用结果稳定（第二次返回 0）。
func (m *SessionManager) EndOtherSessions(account, keepFamilyID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	ended := 0
	for _, fam := range m.families {
		if fam.account != account || fam.revoked || fam.id == keepFamilyID {
			continue
		}
		fam.revoked = true
		fam.endKind = EndByUser
		m.recordLocked(fam, EventEndedByUser,
			fmt.Sprintf("用户一键结束其他会话（保留 %s）", keepFamilyID))
		ended++
	}
	return ended
}

// FamilyIDOf 返回访问令牌所属的会话族 ID，供"结束其他会话"定位当前会话。
func (m *SessionManager) FamilyIDOf(accessToken string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.accessIndex[accessToken]
	if !ok {
		return "", false
	}
	return rec.familyID, true
}

// Events 返回账号的会话活动记录（只读副本，按时间升序）。
// 每条记录带有当时的配置快照，配置变更后历史仍可解释。
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

// enforceCapacityLocked 回收账号超额的活跃会话：最近最久未使用者优先被回收。
// 调用方须持有 m.mu。
func (m *SessionManager) enforceCapacityLocked(account string) {
	if m.maxSessions <= 0 {
		return
	}
	var active []*sessionFamily
	for _, fam := range m.families {
		if fam.account == account && !fam.revoked {
			active = append(active, fam)
		}
	}
	if len(active) <= m.maxSessions {
		return
	}
	// 最近最久未使用优先回收；并列时建立早者优先；再并列按 ID 保证确定性
	sort.Slice(active, func(i, j int) bool {
		if !active[i].lastActiveAt.Equal(active[j].lastActiveAt) {
			return active[i].lastActiveAt.Before(active[j].lastActiveAt)
		}
		if !active[i].createdAt.Equal(active[j].createdAt) {
			return active[i].createdAt.Before(active[j].createdAt)
		}
		return active[i].id < active[j].id
	})
	for _, fam := range active[:len(active)-m.maxSessions] {
		fam.revoked = true
		fam.endKind = EndEvicted
		m.recordLocked(fam, EventEvicted,
			fmt.Sprintf("账号活跃会话数超过上限 %d，按最近最久未使用规则回收（该会话最近活动于 %s）",
				m.maxSessions, fam.lastActiveAt.Format(time.RFC3339)))
	}
}

// recordLocked 追加一条活动记录，带上当前配置快照。调用方须持有 m.mu。
func (m *SessionManager) recordLocked(fam *sessionFamily, kind EventKind, detail string) {
	m.events = append(m.events, SessionEvent{
		Time: m.clock(), Account: fam.account, FamilyID: fam.id,
		Kind: kind, Detail: detail,
		MaxSessions: m.maxSessions, AccessTTL: m.accessTTL, RefreshTTL: m.refreshTTL,
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
