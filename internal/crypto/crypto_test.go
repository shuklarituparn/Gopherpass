package crypto

import (
	"testing"
)

func TestNewEncryptor(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantErr error
	}{
		{
			name:    "valid key",
			key:     "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: ErrEmptyKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := NewEncryptor(tt.key)
			if err != tt.wantErr {
				t.Errorf("NewEncryptor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && enc == nil {
				t.Error("NewEncryptor() returned nil encryptor for valid key")
			}
		})
	}
}

func TestEncryptor_EncryptDecrypt(t *testing.T) {
	enc, err := NewEncryptor("test-encryption-key")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "empty data",
			plaintext: []byte(""),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name:      "long text",
			plaintext: []byte("This is a longer piece of text that we want to encrypt and decrypt to make sure everything works correctly with larger payloads."),
		},
		{
			name:      "unicode text",
			plaintext: []byte("Привет мир! 你好世界! مرحبا بالعالم"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Errorf("Encrypt() error = %v", err)
				return
			}

			decrypted, err := enc.Decrypt(encrypted)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}

			if string(decrypted) != string(tt.plaintext) {
				t.Errorf("Decrypt() got = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptor_EncryptDecryptBytes(t *testing.T) {
	enc, err := NewEncryptor("test-encryption-key")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "empty data",
			plaintext: []byte(""),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := enc.EncryptBytes(tt.plaintext)
			if err != nil {
				t.Errorf("EncryptBytes() error = %v", err)
				return
			}

			decrypted, err := enc.DecryptBytes(encrypted)
			if err != nil {
				t.Errorf("DecryptBytes() error = %v", err)
				return
			}

			if string(decrypted) != string(tt.plaintext) {
				t.Errorf("DecryptBytes() got = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptor_DecryptInvalidData(t *testing.T) {
	enc, err := NewEncryptor("test-key")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
	}{
		{
			name:       "invalid base64",
			ciphertext: "not-valid-base64!!!",
		},
		{
			name:       "too short ciphertext",
			ciphertext: "YWJj", 
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := enc.Decrypt(tt.ciphertext)
			if err == nil {
				t.Error("Decrypt() expected error for invalid data")
			}
		})
	}
}

func TestEncryptor_DecryptBytesInvalidData(t *testing.T) {
	enc, err := NewEncryptor("test-key")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	_, err = enc.DecryptBytes([]byte{1, 2, 3})
	if err != ErrInvalidCiphertext {
		t.Errorf("DecryptBytes() error = %v, want %v", err, ErrInvalidCiphertext)
	}
}

func TestEncryptor_DifferentKeys(t *testing.T) {
	enc1, _ := NewEncryptor("key1")
	enc2, _ := NewEncryptor("key2")

	plaintext := []byte("secret data")

	encrypted, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = enc2.Decrypt(encrypted)
	if err == nil {
		t.Error("Decrypt() should fail with different key")
	}
}

func TestHashPassword(t *testing.T) {
	password := "my-secure-password"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if hash == "" {
		t.Error("HashPassword() returned empty hash")
	}

	if hash == password {
		t.Error("HashPassword() hash equals plaintext password")
	}
}

func TestCheckPassword(t *testing.T) {
	password := "my-secure-password"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	err = CheckPassword(password, hash)
	if err != nil {
		t.Errorf("CheckPassword() error = %v for correct password", err)
	}

	err = CheckPassword("wrong-password", hash)
	if err == nil {
		t.Error("CheckPassword() should return error for wrong password")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	tests := []int{16, 32, 64, 128}

	for _, length := range tests {
		t.Run("", func(t *testing.T) {
			bytes, err := GenerateRandomBytes(length)
			if err != nil {
				t.Errorf("GenerateRandomBytes() error = %v", err)
				return
			}

			if len(bytes) != length {
				t.Errorf("GenerateRandomBytes() length = %d, want %d", len(bytes), length)
			}
		})
	}

	b1, _ := GenerateRandomBytes(32)
	b2, _ := GenerateRandomBytes(32)

	equal := true
	for i := range b1 {
		if b1[i] != b2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("GenerateRandomBytes() returned same bytes twice")
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []int{8, 16, 32, 64}

	for _, length := range tests {
		t.Run("", func(t *testing.T) {
			str, err := GenerateRandomString(length)
			if err != nil {
				t.Errorf("GenerateRandomString() error = %v", err)
				return
			}

			if len(str) != length {
				t.Errorf("GenerateRandomString() length = %d, want %d", len(str), length)
			}
		})
	}

	s1, _ := GenerateRandomString(32)
	s2, _ := GenerateRandomString(32)

	if s1 == s2 {
		t.Error("GenerateRandomString() returned same string twice")
	}
}

func TestDeriveKey(t *testing.T) {
	masterKey := "my-master-key"
	salt1 := "salt1"
	salt2 := "salt2"

	key1 := DeriveKey(masterKey, salt1)
	key2 := DeriveKey(masterKey, salt2)
	key3 := DeriveKey(masterKey, salt1)

	if string(key1) != string(key3) {
		t.Error("DeriveKey() same inputs produced different outputs")
	}

	if string(key1) == string(key2) {
		t.Error("DeriveKey() different salts produced same key")
	}

	if len(key1) != 32 {
		t.Errorf("DeriveKey() length = %d, want 32", len(key1))
	}
}

func BenchmarkEncrypt(b *testing.B) {
	enc, _ := NewEncryptor("benchmark-key")
	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Encrypt(data)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	enc, _ := NewEncryptor("benchmark-key")
	data := make([]byte, 1024)
	encrypted, _ := enc.Encrypt(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enc.Decrypt(encrypted)
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "benchmark-password"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = HashPassword(password)
	}
}
