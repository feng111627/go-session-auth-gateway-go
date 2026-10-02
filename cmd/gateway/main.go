// 本地演示：完整走一遍 登录 -> 多因素 -> 访问 -> 刷新 -> 重放检测 的流程。
package main

import (
	"fmt"
	"time"

	"github.com/feng111627/go-session-auth-gateway-go/gateway"
)

func main() {
	users := []gateway.User{
		{Account: "alice", Password: "pw123", Roles: []string{"reader"}},
		{Account: "bob", Password: "pw456", Roles: []string{"admin"}},
	}
	otp := gateway.NewOTPStore(30*time.Second, nil)
	auth := gateway.NewAuthenticator(users, otp,
		gateway.LoginConfig{MaxFailures: 3, LockDuration: time.Minute}, nil)
	g := gateway.NewGateway(
		gateway.NewRateLimiter(5, time.Minute, nil),
		auth,
		gateway.NewSessionManager(time.Minute, time.Hour, nil),
		gateway.NewAuthorizer([]gateway.PolicyRule{
			{Role: "reader", Resource: "doc", Action: "read", Scene: "normal", Allow: true},
			{Role: "reader", Resource: "doc", Action: "write", Scene: "normal", Allow: false},
			{Role: "admin", Resource: "doc", Action: "write", Scene: "normal", Allow: true},
		}),
	)

	fmt.Println("== 1. 登录：密码 + 多因素 ==")
	res := g.Login("alice", "web", "pw123")
	fmt.Println("密码阶段:", res.Detail)
	code := otp.LastCode("alice") // 演示：取回刚签发的动态码
	res, pair := g.VerifyOTP("alice", "web", code)
	fmt.Println("多因素阶段:", res.Detail)

	fmt.Println("\n== 2. 授权访问 ==")
	d := g.Access("alice", "web", pair.AccessToken, "doc", "read", "normal")
	fmt.Println("reader 读 doc:", d.Result.Detail)
	d = g.Access("alice", "web", pair.AccessToken, "doc", "write", "normal")
	fmt.Println("reader 写 doc:", d.Result.Reason, "-", d.Result.Detail)

	fmt.Println("\n== 3. 会话刷新与重放检测 ==")
	res, pair2 := g.Sessions.Refresh(pair.RefreshToken)
	fmt.Println("正常轮换:", res.Detail)
	res, _ = g.Sessions.Refresh(pair.RefreshToken) // 宽限期内重放：拒绝但不撤销
	fmt.Println("宽限期内重放旧令牌:", res.Reason, "-", res.Detail)
	time.Sleep(6 * time.Second)                    // 超过宽限期
	res, _ = g.Sessions.Refresh(pair.RefreshToken) // 宽限期外重放：撤销会话族
	fmt.Println("宽限期外重放旧令牌:", res.Reason, "-", res.Detail)
	fmt.Println("会话族可疑标记:", g.Sessions.IsSuspicious(pair2.RefreshToken))

	fmt.Println("\n== 4. 会话总览与集中结束 ==")
	g.Login("alice", "app", "pw123")
	_, pairApp := g.VerifyOTP("alice", "app", otp.LastCode("alice"))
	g.Login("alice", "pad", "pw123")
	_, pairPad := g.VerifyOTP("alice", "pad", otp.LastCode("alice"))
	for _, s := range g.ListSessions("alice") {
		fmt.Printf("活跃会话: id=%s 入口=%s 建立=%s 最近活动=%s 可疑=%v\n",
			s.ID[:8], s.Source, s.CreatedAt.Format(time.RFC3339), s.LastActiveAt.Format(time.RFC3339), s.Suspicious)
	}
	tr := g.TerminateSession("alice", mustSessionID(g, pairApp))
	fmt.Println("结束 app 会话:", tr.Status, "-", tr.Detail)
	res, _ = g.Sessions.ValidateAccess(pairApp.AccessToken)
	fmt.Println("结束后用其访问令牌:", res.Reason, "-", res.Detail)
	res, ended := g.TerminateOtherSessions("alice", pairPad.AccessToken)
	fmt.Println("一键结束其他会话:", res.Detail, "，结束数:", len(ended))

	fmt.Println("\n== 5. 会话容量与自动回收 ==")
	g.Sessions.SetMaxSessions(1)
	g.Login("bob", "web", "pw456")
	_, bobWeb := g.VerifyOTP("bob", "web", otp.LastCode("bob"))
	g.Login("bob", "app", "pw456")
	g.VerifyOTP("bob", "app", otp.LastCode("bob")) // 到顶后再登录，回收最久未使用的 web 会话
	res, _ = g.Sessions.ValidateAccess(bobWeb.AccessToken)
	fmt.Println("被回收会话的访问令牌:", res.Reason, "-", res.Detail)

	fmt.Println("\n== 6. 会话活动追溯 ==")
	for _, e := range g.SessionEvents("bob") {
		fmt.Printf("事件: %s 会话=%s 依据=%s (当时上限=%d)\n",
			e.Kind, e.SessionID[:8], e.Detail, e.Config.MaxSessionsPerAccount)
	}
}

func mustSessionID(g *gateway.Gateway, p gateway.TokenPair) string {
	id, _ := g.Sessions.SessionIDOf(p.AccessToken)
	return id
}
