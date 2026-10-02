package user

import "sync"

// Role 是本地模拟的角色。
type Role struct {
	ID     string
	Name   string
	Scopes []string
}

// User 是本地模拟的账号，PasswordHash 与 MFASecret 均为本地模拟数据，
// 不是真实凭据：PasswordHash 直接存“模拟哈希”（见 VerifyPassword）。
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Roles        []string
	MFASecret    string
}

// Store 是并发安全的内存用户/角色存储。
type Store struct {
	mu    sync.RWMutex
	users map[string]User // key: username
	roles map[string]Role // key: roleID
}

// NewStore 创建空存储。
func NewStore() *Store {
	return &Store{
		users: make(map[string]User),
		roles: make(map[string]Role),
	}
}

// AddRole 写入或覆盖一个角色。
func (s *Store) AddRole(r Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles[r.ID] = r
}

// AddUser 写入或覆盖一个用户。
func (s *Store) AddUser(u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Username] = u
}

// FindByUsername 按用户名查询。
func (s *Store) FindByUsername(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

// FindByID 按用户 ID 查询。
func (s *Store) FindByID(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

// Role 按 ID 查询角色。
func (s *Store) Role(id string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[id]
	return r, ok
}

// VerifyPassword 是本地模拟的密码校验：
// 入参 password 经过 FakeHash 后与存储的模拟哈希比较，全程不接触任何真实凭据系统。
func VerifyPassword(u User, password string) bool {
	return u.PasswordHash == FakeHash(password)
}

// FakeHash 返回本地演示用的确定性“哈希”。
func FakeHash(password string) string {
	return "fake$" + password
}
