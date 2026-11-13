package store

const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusError   = "error"
	StatusLocked  = "locked" // 到期回收：OS 账户已被锁定，等待管理员删除或续期

	ModeReadWrite = "rw"
	ModeReadOnly  = "ro"

	// 服务器管理账户能力级别（测试连通时探测写入）。
	AccessRoot  = "root"
	AccessSudo  = "sudo"
	AccessPlain = "plain" // attach-only：无特权账户，不建/删 OS 用户，仅授撤自己目录的 ACL
)

type Server struct {
	ID              string
	Name            string
	Host            string
	SSHPort         int
	RootUser        string
	RootPasswordEnc []byte
	HostKey         string
	Enabled         bool
	LastVerifiedAt  string // RFC3339，空串表示未验证
	// AccessMode 管理账户能力级别：root | sudo | plain（attach-only）。空串 = 尚未探测。
	AccessMode string
	CreatedAt  string
	UpdatedAt  string
}

type Account struct {
	ID             string
	ServerID       string
	Username       string
	PasswordEnc    []byte
	CodingCapable  bool
	ExposedToAgent bool
	Status         string
	LastError      string
	// ExpiresAt 为 RFC3339 时刻，空串表示永不到期；到期后账户不再经 MCP 暴露，
	// 由后台回收器锁定 OS 账户。
	ExpiresAt string
	CreatedAt string
	UpdatedAt string
}

type DirectoryPermission struct {
	ID        string
	AccountID string
	Path      string
	Mode      string
}

type ExposedAccount struct {
	ServerID      string
	ServerName    string
	Host          string
	SSHPort       int
	AccountID     string
	Username      string
	PasswordEnc   []byte
	CodingCapable bool
	Directories   []DirectoryPermission
}

type Admin struct {
	Username     string
	PasswordHash string
}
