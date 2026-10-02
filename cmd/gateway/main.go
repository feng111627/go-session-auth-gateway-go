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
	// 再从另外两个入口登录，形成多会话
	g.Login("alice", "mobile", "pw123")
	_, pairM := g.VerifyOTP("alice", "mobile", otp.LastCode("alice"))
	g.Login("alice", "desktop", "pw123")
	_, pairD := g.VerifyOTP("alice", "desktop", otp.LastCode("alice"))
	for _, s := range g.ListSessions("alice") {
		fmt.Printf("活跃会话 %s: 入口=%s 建立=%s 最近活动=%s 可疑=%v\n",
			s.ID[:8], s.Source, s.CreatedAt.Format(time.RFC3339),
			s.LastActiveAt.Format(time.RFC3339), s.Suspicious)
	}
	// 单独结束 mobile 会话，其令牌立即失效
	mobileID, _ := g.Sessions.FamilyIDOf(pairM.AccessToken)
	res, outcome := g.EndSession("alice", mobileID)
	fmt.Println("结束 mobile 会话:", res.Detail, " outcome =", outcome)
	res, _ = g.Sessions.ValidateAccess(pairM.AccessToken)
	fmt.Println("结束后用其访问令牌:", res.Reason, "-", res.Detail)
	_, outcome = g.EndSession("alice", mobileID)
	fmt.Println("重复结束同一会话: outcome =", outcome, "（幂等，无副作用）")
	// 一键结束除当前 desktop 会话之外的所有会话
	res, n := g.EndOtherSessions("alice", pairD.AccessToken)
	fmt.Println("一键结束其他会话（保留 desktop）:", res.Detail, " 结束数 =", n)
	for _, s := range g.ListSessions("alice") {
		fmt.Printf("  剩余会话 %s: 入口=%s\n", s.ID[:8], s.Source)
	}

	fmt.Println("\n== 5. 账号会话容量与自动回收 ==")
	g.Sessions.SetMaxSessions(1)
	g.Login("alice", "tablet", "pw123")
	_, pairT := g.VerifyOTP("alice", "tablet", otp.LastCode("alice")) // 超出上限，回收最久未使用者
	fmt.Println("上限设为 1 后再登录，活跃会话：")
	for _, s := range g.ListSessions("alice") {
		fmt.Printf("  %s: 入口=%s 最近活动=%s\n", s.ID[:8], s.Source,
			s.LastActiveAt.Format(time.RFC3339))
	}
	res, _ = g.Sessions.ValidateAccess(pairD.AccessToken)
	fmt.Println("被回收的 desktop 会话访问令牌:", res.Reason, "-", res.Detail)
	res, _ = g.Sessions.ValidateAccess(pairT.AccessToken)
	fmt.Println("新登录的 tablet 会话访问令牌:", res.Detail)

	fmt.Println("\n== 6. 会话活动记录（含判定依据与当时配置快照） ==")
	for _, e := range g.SessionEvents("alice") {
		fmt.Printf("  [%s] 会话=%s %s（当时上限=%d 访问TTL=%s）\n",
			e.Time.Format("15:04:05"), e.FamilyID[:8], e.Detail, e.MaxSessions, e.AccessTTL)
	}
}
