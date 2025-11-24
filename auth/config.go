package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

type AuthConfig struct {
	Enabled bool `yaml:"enabled"`
	// the ed25519 private key used to sign
	PrivateKey string `yaml:"private-key"`
	// The key is used to identify user source so it must be unique
	YggdrasilServers map[string]string `yaml:"yggdrasil-servers"`
	// Bypass limbo authentication for yggdrasil authenticated players.
	YggdrasilBypass bool `yaml:"yggdrasil-bypass"`
	// Bypass limbo authentication for offline players
	OfflineBypass bool `yaml:"offline-bypass"`
	// If yggdrasil authentication is failed, should they join limbo to perform user/pass ?
	// Once the user/pass authentication is passed they got their yggdrasil uuid to join servers.
	// Yggdrasil fallback players have different UUID with the same-name offline players.
	YggdrasilFallback bool `yaml:"yggdrasil-fallback"`
	// Should we only allow the first player that use this name to authenticate?
	AllowNameCollision bool `yaml:"allow-name-collision"`
	// Should we allow registration for new users?
	// If not, they will be asked for an invitation code, which can be generated from console.
	OpenRegistration bool           `yaml:"open-registration"`
	Database         DatabaseConfig `yaml:"database"`
}

type DatabaseConfig struct {
	Driver  string `yaml:"driver"`
	Connect string `yaml:"connect"`
}

func NewAuthConfig() *AuthConfig {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &AuthConfig{
		Enabled:    true,
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		YggdrasilServers: map[string]string{
			"mojang": "https://sessionserver.mojang.com/",
		},
		YggdrasilBypass:    true,
		OfflineBypass:      false,
		YggdrasilFallback:  false,
		AllowNameCollision: false,
		OpenRegistration:   true,
		Database: DatabaseConfig{
			Driver:  "sqlite3",
			Connect: "file:test.db?cache=shared&mode=memory",
		},
	}
}
