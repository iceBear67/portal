package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/go-mc/server/limbo"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type AuthServer struct {
	server         *limbo.Server
	config         *AuthConfig
	registerQueue  chan *RegisterRequest
	database       *sqlx.DB
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	bindingPlayers map[string]uuid.UUID
}

func NewAuthServer(server *limbo.Server, config *AuthConfig) (*AuthServer, error) {
	privKey, err := base64.StdEncoding.DecodeString(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	db, err := sqlx.Open(config.Database.Driver, config.Database.Connect)
	if err != nil {
		return nil, err
	}
	writer, err := createWriter(db, server.Ctx())
	if err != nil {
		return nil, err
	}
	for k := range config.YggdrasilServers {
		if k == "offline" {
			return nil, fmt.Errorf("yggdrasil server cannot be named 'offline'")
		}
	}
	return &AuthServer{
		server:        server,
		config:        config,
		privateKey:    privKey,
		publicKey:     ed25519.PrivateKey(privKey).Public().(ed25519.PublicKey),
		registerQueue: writer,
		database:      db,
	}, nil
}

func (s *AuthServer) Start() error {
	s.server.SetupListener(s)
	_, err := s.database.Exec(SQLiteSchema)
	if err != nil {
		return err
	}

	return s.server.Start()
}

func (s *AuthServer) OnNewConnection(conn *limbo.PortalConn) bool {
	if s.config.Enabled {
		conn.SetupListener(&AuthConnHandler{server: s, authSource: ""})
	}
	return true
}

func (s *AuthServer) OnDisconnect(conn *limbo.PortalConn) {

}
