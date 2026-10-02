package gateway

import (
	"testing"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/internal/authz"
	"github.com/feng111627/go-session-auth-gateway-go/internal/login"
	"github.com/feng111627/go-session-auth-gateway-go/internal/mfa"
	"github.com/feng111627/go-session-auth-gateway-go/internal/ratelimit"
	"github.com/feng111627/go-session-auth-gateway-go/internal/session"
	"github.com/feng111627/go-session-auth-gateway-go/internal/user"
)

type testEnv struct {
	gw   *Gateway
	now  time.Time
	step func(d time.Duration)
}

// newTestEnv 装配一套全部组件共享同一个可控时钟的网关。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	clock := &struct{ t time.Time }{t: base}
	now := func() time.Time { return clock.t }

	users := user.NewStore()
	users.AddRole(user.Role{ID: "admin", Name: "Administrator"})
	users.AddRole(user.Role{ID: "member", Name: "Member"})
	users.AddUser(user.User{
		ID: "u-alice", Username: "alice",
		PasswordHash: user.FakeHash("correct horse"),
		Roles:        []string{"member"}, MFASecret: "secret-alice",
	})
	users.AddUser(user.User{
		ID: "u-admin", Username: "root",
		PasswordHash: user.FakeHash("admin pass"),
		Roles:        []string{"admin"}, MFASecret: "secret-root",
	})
	users.AddUser(user.User{
		ID: "u-bob", Username: "bob",
		PasswordHash: user.FakeHash("bob pw"),
		Roles:        []string{"member"}, MFASecret: "secret-bob",
	})

	mfaSvc := mfa.NewService(2 * time.Minute)
	loginSvc := login.NewService(users, mfaSvc, login.Config{
		MaxFailures: 3, LockDuration: 5 * time.Minute,
	})
	sessions := session.NewManager(10*time.Minute, 30*time.Minute, now)
	limiter := ratelimit.New(3, 5, time.Minute, now)

	policy := authz.Policy{
		Version: 1,
		Rules: []authz.Rule{
			{ID: "r-admin-all", Role: "admin", Resource: "/admin/*", Action: "*",
				Scenarios: []authz.Scenario{authz.ScenarioAdmin, authz.ScenarioAPI}, Effect: "allow"},
			{ID: "r-member-api", Role: "member", Resource: "/api/*", Action: "*",
				Scenarios: []authz.Scenario{authz.ScenarioAPI}, Effect: "allow"},
			{ID: "r-member-self-profile", Role: "member", Resource: "/api/profile/self", Action: "GET",
				Scenarios: []authz.Scenario{authz.ScenarioAPI}, Effect: "allow"},
			{ID: "r-deny-member-admin", Role: "member", Resource: "/admin/*", Action: "*",
				Scenarios: []authz.Scenario{authz.ScenarioAdmin, authz.ScenarioAPI}, Effect: "deny"},
		},
	}
	engine := authz.NewEngine(policy, now)

	gw := New(users, mfaSvc, loginSvc, sessions, limiter, engine, now)
	env := &testEnv{gw: gw, now: base}
	env.step = func(d time.Duration) {
		clock.t = clock.t.Add(d)
		env.now = clock.t
	}
	return env
}
