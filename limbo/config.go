package limbo

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-mc/server/limbo/slp"
)

type PortalConfig struct {
	Listen          string                   `yaml:"listen"`
	FallbackServer  string                   `yaml:"fallback-server"`
	CacheInvalidate time.Duration            `yaml:"cache-invalidate-time"`
	Servers         map[string]*ServerConfig `yaml:"servers"`
	DefaultInfo     slp.ServerListPing       `yaml:"default-info"`
	DefaultSkin     string                   `yaml:"default-skin"`
	AuthTimeout     time.Duration            `yaml:"auth-timeout"`
	StatusTimeout   time.Duration            `yaml:"status-timeout"`
	Keepalive       time.Duration            `yaml:"keepalive-interval-sec"`
	PrivateKey      EncodedPrivateKey        `yaml:"seed"`
	RegistryData    map[int]string           `yaml:"registry-data"`
}

type ServerConfig struct {
	Match           string           `yaml:"match"`
	DestinationHost string           `yaml:"host"`
	DestinationPort int              `yaml:"port"`
	PublicKey       EncodedPublicKey `yaml:"public-key"`
	PreferProxy     bool             `yaml:"prefer-proxy"`
}

// MatchServer resolves a client-requested hostname to a configured server by
// comparing it against each server's Match field. It returns the server's name
// (its key in Servers) alongside its config; ok is false when nothing matches.
//
// Server lookups must go through here rather than indexing Servers by the
// requested host directly: the map key is an internal name, while Match is what
// the incoming hostname is routed against.
func (c *PortalConfig) MatchServer(host string) (name string, server *ServerConfig, ok bool) {
	for n, s := range c.Servers {
		if s.Match == host {
			return n, s, true
		}
	}
	return "", nil, false
}

type EncodedPrivateKey ed25519.PrivateKey

func (c EncodedPrivateKey) MarshalYAML() (interface{}, error) {
	encodedKey := ""
	if len(c) == ed25519.PrivateKeySize {
		// store only the 32-byte seed; the full key is derived on load
		encodedKey = base64.StdEncoding.EncodeToString(ed25519.PrivateKey(c).Seed())
	}
	return encodedKey, nil
}

func (c *EncodedPrivateKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var encodedSeed string
	if err := unmarshal(&encodedSeed); err != nil {
		return err
	}

	if encodedSeed == "" {
		*c = nil
		return nil
	}

	seed, err := base64.StdEncoding.DecodeString(encodedSeed)
	if err != nil {
		return err
	}

	if len(seed) != ed25519.SeedSize {
		return errors.New("invalid ed25519 seed size")
	}

	*c = EncodedPrivateKey(ed25519.NewKeyFromSeed(seed))
	return nil
}

type EncodedPublicKey ed25519.PublicKey

func (c EncodedPublicKey) MarshalYAML() (interface{}, error) {
	encodedKey := ""
	if len(c) > 0 {
		encodedKey = base64.StdEncoding.EncodeToString(c)
	}
	return encodedKey, nil
}

func (c *EncodedPublicKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var encodedKey string
	if err := unmarshal(&encodedKey); err != nil {
		return err
	}

	if encodedKey == "" {
		*c = nil
		return nil
	}

	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return err
	}

	if len(decodedKey) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 public key size")
	}

	*c = append((*c)[:0], decodedKey...)
	return nil
}
