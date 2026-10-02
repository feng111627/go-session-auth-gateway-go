package gateway

import (
	"fmt"
	"strings"
	"sync"
)

// PolicyRule 一条授权规则：某角色在某场景下对某资源动作是否放行。
type PolicyRule struct {
	Role     string
	Resource string
	Action   string
	Scene    string // 使用场景，如 "normal"、"emergency"
	Allow    bool
}

func (r PolicyRule) String() string {
	verb := "DENY "
	if r.Allow {
		verb = "ALLOW"
	}
	return fmt.Sprintf("%s role=%s %s:%s scene=%s", verb, r.Role, r.Resource, r.Action, r.Scene)
}

// Decision 是一次授权判定的不可变记录，含策略版本与命中规则快照，
// 策略更新后历史判定仍可解释。
type Decision struct {
	Result
	PolicyVersion int
	MatchedRule   *PolicyRule // nil 表示无规则命中（默认拒绝）
}

// Authorizer 基于角色与场景做授权判定，并记录判定历史。
type Authorizer struct {
	mu        sync.RWMutex
	rules     []PolicyRule
	version   int
	decisions []Decision
}

// NewAuthorizer 创建授权器，初始策略版本为 1。
func NewAuthorizer(rules []PolicyRule) *Authorizer {
	a := &Authorizer{version: 1}
	a.rules = append([]PolicyRule(nil), rules...)
	return a
}

// UpdatePolicy 整体替换策略，版本号递增；已记录的历史判定不受影响。
func (a *Authorizer) UpdatePolicy(rules []PolicyRule) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append([]PolicyRule(nil), rules...)
	a.version++
}

// Authorize 判定 roles 中的任一角色是否允许在 scene 下对 resource 做 action。
// 命中显式 DENY 规则与无规则命中的默认拒绝会体现在 MatchedRule 上。
func (a *Authorizer) Authorize(roles []string, resource, action, scene string) Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := Decision{PolicyVersion: a.version}
	for i := range a.rules {
		r := a.rules[i]
		if r.Resource != resource || r.Action != action || r.Scene != scene {
			continue
		}
		if !hasRole(roles, r.Role) {
			continue
		}
		rule := r // 快照，策略更新后历史判定仍引用旧规则
		d.MatchedRule = &rule
		if r.Allow {
			d.Result = Allow(fmt.Sprintf("命中规则[%s]", r))
		} else {
			d.Result = Reject(ReasonForbidden, fmt.Sprintf("命中显式拒绝规则[%s]", r))
		}
		a.decisions = append(a.decisions, d)
		return d
	}
	d.Result = Reject(ReasonForbidden,
		fmt.Sprintf("无规则允许角色[%s]在场景 %s 下对 %s 执行 %s，默认拒绝",
			strings.Join(roles, ","), scene, resource, action))
	a.decisions = append(a.decisions, d)
	return d
}

// Decisions 返回全部历史判定记录（只读副本）。
func (a *Authorizer) Decisions() []Decision {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]Decision(nil), a.decisions...)
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
