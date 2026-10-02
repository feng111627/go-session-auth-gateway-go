// 本地登录认证与授权网关演示。
//
// 全部数据（用户、角色、策略、令牌、验证码、计数）都在进程内存中模拟，
// 不依赖任何外部服务或真实凭据。
//
// 快速体验见 README.md，端点：
//
//	POST /demo/mfa-code   为本地演示签发当前一次性动态码
//	POST /login           密码 + 动态码登录，返回访问/刷新令牌
//	POST /refresh         刷新令牌轮换
//	POST /access          携带访问令牌访问资源
//	GET  /decisions       查看历史授权判定（可解释依据）
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/internal/authz"
	"github.com/feng111627/go-session-auth-gateway-go/internal/gateway"
	"github.com/feng111627/go-session-auth-gateway-go/internal/login"
	"github.com/feng111627/go-session-auth-gateway-go/internal/mfa"
	"github.com/feng111627/go-session-auth-gateway-go/internal/ratelimit"
	"github.com/feng111627/go-session-auth-gateway-go/internal/session"
	"github.com/feng111627/go-session-auth-gateway-go/internal/user"
)

func main() {
	now := time.Now

	users := user.NewStore()
	users.AddRole(user.Role{ID: "admin", Name: "Administrator"})
	users.AddRole(user.Role{ID: "member", Name: "Member"})
	users.AddUser(user.User{ID: "u-alice", Username: "alice",
		PasswordHash: user.FakeHash("correct horse"), Roles: []string{"member"}, MFASecret: "secret-alice"})
	users.AddUser(user.User{ID: "u-root", Username: "root",
		PasswordHash: user.FakeHash("admin pass"), Roles: []string{"admin"}, MFASecret: "secret-root"})

	mfaSvc := mfa.NewService(2 * time.Minute)
	loginSvc := login.NewService(users, mfaSvc, login.Config{MaxFailures: 3, LockDuration: 5 * time.Minute})
	sessions := session.NewManager(10*time.Minute, 30*time.Minute, now)
	limiter := ratelimit.New(5, 20, time.Minute, now)
	engine := authz.NewEngine(authz.Policy{
		Version: 1,
		Rules: []authz.Rule{
			{ID: "r-admin-all", Role: "admin", Resource: "/admin/*", Action: "*",
				Scenarios: []authz.Scenario{authz.ScenarioAdmin, authz.ScenarioAPI}, Effect: "allow"},
			{ID: "r-member-api", Role: "member", Resource: "/api/*", Action: "*",
				Scenarios: []authz.Scenario{authz.ScenarioAPI}, Effect: "allow"},
			{ID: "r-deny-member-admin", Role: "member", Resource: "/admin/*", Action: "*",
				Scenarios: []authz.Scenario{authz.ScenarioAdmin, authz.ScenarioAPI}, Effect: "deny"},
		},
	}, now)
	gw := gateway.New(users, mfaSvc, loginSvc, sessions, limiter, engine, now)

	mux := http.NewServeMux()

	mux.HandleFunc("/demo/mfa-code", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		code, exp, err := gw.IssueMFACode(req.Username)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, reasonOf(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"username": req.Username, "code": code, "expires_at": exp,
		})
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Code     string `json:"code"`
			Source   string `json:"source"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		log.Printf("login input: user=%s source=%s", req.Username, req.Source)
		pair, err := gw.Login(gateway.LoginRequest{
			Username: req.Username, Password: req.Password, Code: req.Code, Source: req.Source,
		})
		if err != nil {
			log.Printf("login decision: DENY reason=%s", reasonOf(err))
			writeErr(w, http.StatusUnauthorized, reasonOf(err), err.Error())
			return
		}
		log.Printf("login decision: ALLOW session=%s family=%s", pair.SessionID, pair.FamilyID)
		writeJSON(w, http.StatusOK, pair)
	})

	mux.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		pair, err := gw.Refresh(req.RefreshToken)
		if err != nil {
			log.Printf("refresh decision: DENY reason=%s", reasonOf(err))
			writeErr(w, http.StatusUnauthorized, reasonOf(err), err.Error())
			return
		}
		log.Printf("refresh decision: ALLOW rotated session=%s", pair.SessionID)
		writeJSON(w, http.StatusOK, pair)
	})

	mux.HandleFunc("/access", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AccessToken string `json:"access_token"`
			Account     string `json:"account"`
			Resource    string `json:"resource"`
			Action      string `json:"action"`
			Scenario    string `json:"scenario"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		log.Printf("access input: account=%s resource=%s action=%s scenario=%s",
			req.Account, req.Resource, req.Action, req.Scenario)
		d, err := gw.Access(gateway.AccessRequest{
			AccessToken: req.AccessToken, Account: req.Account,
			Resource: req.Resource, Action: req.Action, Scenario: authz.Scenario(req.Scenario),
		})
		if err != nil {
			log.Printf("access decision: DENY reason=%s", reasonOf(err))
			writeErr(w, http.StatusTooManyRequests, reasonOf(err), err.Error())
			return
		}
		log.Printf("access decision: id=%s allowed=%v reason=%s matched=%v policy=v%d",
			d.ID, d.Allowed, d.Reason, d.MatchedRules, d.PolicyVersion)
		status := http.StatusOK
		if !d.Allowed {
			status = http.StatusForbidden
		}
		writeJSON(w, status, d)
	})

	mux.HandleFunc("/decisions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"history": engine.History()})
	})

	addr := ":8080"
	log.Printf("demo gateway listening on %s (users: alice/correct horse, root/admin pass)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, reason, detail string) {
	writeJSON(w, status, map[string]string{"error": reason, "detail": detail})
}

// reasonOf 从各阶段的结构化错误中提取可断言的原因码。
func reasonOf(err error) string {
	switch e := err.(type) {
	case *login.DenyError:
		return string(e.Reason)
	case *mfa.Error:
		return string(e.Reason)
	case *session.Error:
		return string(e.Reason)
	case *gateway.RateLimitError:
		return e.Verdict.Reason
	default:
		return "error"
	}
}
