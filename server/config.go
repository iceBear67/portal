package server

import (
	"time"

	"github.com/go-mc/server/server/slp"
)

type PortalConfig struct {
	Listen          string             `yaml:"listen"`
	FallbackServer  string             `yaml:"fallback-server"`
	CacheInvalidate time.Duration      `yaml:"cache-invalidate-time"`
	Servers         map[string]string  `yaml:"servers"`
	DefaultInfo     slp.ServerListPing `yaml:"default-info"`
	DefaultSkin     string             `yaml:"default-skin"`
	AuthTimeout     time.Duration      `yaml:"auth-timeout"`
	Keepalive       time.Duration      `yaml:"keepalive-interval-sec"`
	RegistryData    map[int]string     `yaml:"registry-data"`
}
