package auth

import (
	"crypto/ed25519"
	"encoding/base64"

	"github.com/go-mc/server/limbo"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type AuthServer struct {
	server        *limbo.Server
	config        *AuthConfig
	registerQueue chan *RegisterRequest
	database      *sqlx.DB
	privateKey    ed25519.PrivateKey
	publicKey     ed25519.PublicKey
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
	db, err := sqlx.Open("sqlite3", ":memory:")
	if err != nil {
		return err
	}
	_, err = db.Exec(SQLiteSchema)
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
