package models

import (
	"time"
)

type DataType int

const (
	DataTypeLoginPassword DataType = iota + 1
	DataTypeText
	DataTypeBinary
	DataTypeCard
)

func (dt DataType) String() string {
	switch dt {
	case DataTypeLoginPassword:
		return "login_password"
	case DataTypeText:
		return "text"
	case DataTypeBinary:
		return "binary"
	case DataTypeCard:
		return "card"
	default:
		return "unknown"
	}
}

func ParseDataType(s string) DataType {
	switch s {
	case "login_password":
		return DataTypeLoginPassword
	case "text":
		return DataTypeText
	case "binary":
		return DataTypeBinary
	case "card":
		return DataTypeCard
	default:
		return 0
	}
}

type User struct {
	ID           int64     `json:"id" db:"id"`
	Login        string    `json:"login" db:"login"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}


type Secret struct {
	ID            string    `json:"id" db:"id"`
	UserID        int64     `json:"user_id" db:"user_id"`
	Name          string    `json:"name" db:"name"`
	DataType      DataType  `json:"data_type" db:"data_type"`
	EncryptedData []byte    `json:"encrypted_data" db:"encrypted_data"`
	Metadata      string    `json:"metadata" db:"metadata"`
	Version       int64     `json:"version" db:"version"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

type LoginPassword struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
}

type TextData struct {
	Text string `json:"text"`
}

type BinaryData struct {
	Data     []byte `json:"data"`
	FileName string `json:"file_name,omitempty"`
}

type CardData struct {
	Number     string `json:"number"`
	Holder     string `json:"holder"`
	ExpiryDate string `json:"expiry_date"` // Format: MM/YY
	CVV        string `json:"cvv"`
}

type Metadata struct {
	Website     string            `json:"website,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Custom      map[string]string `json:"custom,omitempty"`
}

type SyncData struct {
	Secrets       []Secret  `json:"secrets"`
	LastSyncTime  time.Time `json:"last_sync_time"`
	ClientVersion string    `json:"client_version"`
}

type SyncResponse struct {
	UpdatedSecrets []Secret  `json:"updated_secrets"`
	DeletedIDs     []string  `json:"deleted_ids"`
	ServerTime     time.Time `json:"server_time"`
	HasConflicts   bool      `json:"has_conflicts"`
}

type AuthRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	UserID    int64     `json:"user_id"`
}

type RegisterRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	UserID int64  `json:"user_id"`
	Token  string `json:"token"`
}
