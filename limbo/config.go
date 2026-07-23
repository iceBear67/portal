package limbo

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/go-mc/server/limbo/slp"
	"gopkg.in/yaml.v3"
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
	PrivateKey      EncodedPrivateKey        `yaml:"private-key"`
	RegistryData    map[int]string           `yaml:"registry-data"`
}

type ServerConfig struct {
	Match           string           `yaml:"match"`
	DestinationHost string           `yaml:"host"`
	DestinationPort int              `yaml:"port"`
	PublicKey       EncodedPublicKey `yaml:"public-key"`
}

type EncodedPrivateKey ed25519.PrivateKey

func (c EncodedPrivateKey) MarshalYAML() (interface{}, error) {
	encodedKey := ""
	if len(c) > 0 {
		encodedKey = base64.StdEncoding.EncodeToString(c)
	}
	return encodedKey, nil
}

func (c *EncodedPrivateKey) UnmarshalYAML(node *yaml.Node) error {
	var encodedKey string
	if err := node.Decode(&encodedKey); err != nil {
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

	if len(decodedKey) != ed25519.PrivateKeySize {
		return errors.New("invalid ed25519 private key size")
	}

	*c = append((*c)[:0], decodedKey...)
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

func (c *EncodedPublicKey) UnmarshalYAML(node *yaml.Node) error {
	var encodedKey string
	if err := node.Decode(&encodedKey); err != nil {
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
