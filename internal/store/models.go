package store

const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusError   = "error"

	ModeReadWrite = "rw"
	ModeReadOnly  = "ro"
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
	CreatedAt       string
	UpdatedAt       string
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
	CreatedAt      string
	UpdatedAt      string
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
