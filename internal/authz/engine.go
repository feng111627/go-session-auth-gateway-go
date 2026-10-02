package authz

import (
	"fmt"
	"path"
	"sync"
	"time"
)

// Scenario 使用场景。
type Scenario string

const (
	ScenarioAPI   Scenario = "api"
	ScenarioAdmin Scenario = "admin"
)

// SubjectStatus 访问时会话的状态（由网关在调授权前给出）。
type SubjectStatus string

const (
	StatusActive  SubjectStatus = "active"
	StatusExpired SubjectStatus = "token_expired"
	StatusRevoked SubjectStatus = "session_revoked"
	StatusUnknown SubjectStatus = "token_unknown"
)

// 判定原因（可被测试断言区分）。
const (
	ReasonAllowed        = "allowed"
	ReasonDeniedByPolicy = "denied_by_policy" // 越权：没有命中任何允许策略，或命中显式 deny
	ReasonTokenExpired   = "token_expired"
	ReasonSessionRevoked = "session_revoked"
	ReasonTokenUnknown   = "token_unknown"
)

// Input 授权判定输入。
type Input struct {
	Subject  string
	Roles    []string
	Resource string
	Action   string
	Scenario Scenario
	Status   SubjectStatus
}

// Decision 一次不可变的授权判定记录。
// 保存的是判定时的输入快照、策略版本与命中的规则，因此之后策略更新，
// 历史判定仍然可凭 ID 完整解释。
type Decision struct {
	ID            string    `json:"id"`
	Time          time.Time `json:"time"`
	Input         Input     `json:"input"`
	Allowed       bool      `json:"allowed"`
	Reason        string    `json:"reason"`
	PolicyVersion int       `json:"policy_version"`
	MatchedRules  []string  `json:"matched_rules"`
	Explanation   string    `json:"explanation"`
}

// Rule 策略规则。Resource 支持末尾 * 通配（如 /admin/*）。
// Effect 取 "allow" 或 "deny"。
type Rule struct {
	ID        string
	Role      string
	Resource  string
	Action    string
	Scenarios []Scenario
	Effect    string
}

func (r Rule) effectDeny() bool { return r.Effect == "deny" }

// Policy 带版本号的策略集合。
type Policy struct {
	Version int
	Rules   []Rule
}

// Engine 基于角色与场景做授权判定，并留存历史判定快照。
type Engine struct {
	mu      sync.RWMutex
	policy  Policy
	now     func() time.Time
	seq     int
	history []Decision
}

func NewEngine(initial Policy, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}
	return &Engine{policy: initial, now: now}
}

// UpdatePolicy 原子替换策略。新版本必须递增版本号，便于区分判定依据；
// 历史判定记录不受影响。
func (e *Engine) UpdatePolicy(p Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = Policy{Version: p.Version, Rules: append([]Rule(nil), p.Rules...)}
}

// PolicyVersion 返回当前策略版本。
func (e *Engine) PolicyVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy.Version
}

// Authorize 执行一次判定并留存不可变记录。
// 判定顺序：
//  1. 会话状态非 active：直接以 token_expired / session_revoked / token_unknown 拒绝，
//     不进入策略匹配（与“越权”明确区分）；
//  2. 策略匹配采用 deny 优先：命中任何 deny -> 拒绝；
//     否则命中至少一条 allow -> 放行；
//     都没有命中 -> denied_by_policy（越权）。
func (e *Engine) Authorize(in Input, t time.Time) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.seq++
	d := Decision{
		ID:            fmt.Sprintf("dec-%d-%d", e.seq, t.UnixNano()),
		Time:          t,
		Input:         cloneInput(in),
		PolicyVersion: e.policy.Version,
		MatchedRules:  []string{},
	}

	if reason, ok := statusReason(in.Status); !ok {
		d.Allowed = false
		d.Reason = reason
		d.Explanation = fmt.Sprintf("subject status=%s, policy evaluation skipped", in.Status)
		e.history = append(e.history, d)
		return d
	}

	var denyHits, allowHits []string
	for _, r := range e.policy.Rules {
		if !ruleMatches(r, in) {
			continue
		}
		if r.effectDeny() {
			denyHits = append(denyHits, r.ID)
		} else {
			allowHits = append(allowHits, r.ID)
		}
	}
	d.MatchedRules = append(append([]string{}, denyHits...), allowHits...)

	switch {
	case len(denyHits) > 0:
		d.Allowed = false
		d.Reason = ReasonDeniedByPolicy
		d.Explanation = fmt.Sprintf("explicit deny rules matched: %v", denyHits)
	case len(allowHits) > 0:
		d.Allowed = true
		d.Reason = ReasonAllowed
		d.Explanation = fmt.Sprintf("allow rules matched: %v", allowHits)
	default:
		d.Allowed = false
		d.Reason = ReasonDeniedByPolicy
		d.Explanation = fmt.Sprintf("no allow rule matched roles=%v resource=%s action=%s scenario=%s",
			in.Roles, in.Resource, in.Action, in.Scenario)
	}

	e.history = append(e.history, d)
	return d
}

func statusReason(s SubjectStatus) (string, bool) {
	switch s {
	case StatusActive:
		return "", true
	case StatusExpired:
		return ReasonTokenExpired, false
	case StatusRevoked:
		return ReasonSessionRevoked, false
	default:
		return ReasonTokenUnknown, false
	}
}

func ruleMatches(r Rule, in Input) bool {
	if !containsRole(in.Roles, r.Role) {
		return false
	}
	if r.Action != "*" && r.Action != in.Action {
		return false
	}
	if !resourceMatches(r.Resource, in.Resource) {
		return false
	}
	if len(r.Scenarios) > 0 && !containsScenario(r.Scenarios, in.Scenario) {
		return false
	}
	return true
}

func containsRole(roles []string, role string) bool {
	for _, x := range roles {
		if x == role {
			return true
		}
	}
	return false
}

func containsScenario(list []Scenario, s Scenario) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// resourceMatches 支持精确匹配与目录式前缀通配（/admin/* 匹配 /admin/ 下任意层级）。
func resourceMatches(pattern, resource string) bool {
	if pattern == "*" || pattern == resource {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		if ok, err := path.Match(prefix+"*", resource); err == nil && ok {
			return true
		}
		return len(resource) >= len(prefix) && resource[:len(prefix)] == prefix
	}
	return false
}

func cloneInput(in Input) Input {
	in.Roles = append([]string(nil), in.Roles...)
	return in
}

// Explain 按 ID 取回历史判定（快照）。
func (e *Engine) Explain(decisionID string) (Decision, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, d := range e.history {
		if d.ID == decisionID {
			return d, true
		}
	}
	return Decision{}, false
}

// History 返回全部历史判定的拷贝（按时间先后）。
func (e *Engine) History() []Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Decision, len(e.history))
	copy(out, e.history)
	return out
}
