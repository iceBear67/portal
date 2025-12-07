package limbo

import (
	"context"
	"crypto/rsa"

	"github.com/Tnze/go-mc/net"
	"github.com/google/uuid"
)

type PortalConn struct {
	server *Server
	// not valid until login success
	playerId   *uuid.UUID
	playerName string
	online     bool

	// initialized with StateHandshake
	state int

	// not valid until handshake complete
	requestedHost   string
	destination     string
	protocolVersion ProtocolVersion

	// always available
	conn     *net.Conn
	ctx      context.Context
	listener ConnectionListener
}

func (s *PortalConn) Server() *Server {
	return s.server
}

func (s *PortalConn) PlayerId() *uuid.UUID {
	return s.playerId
}

func (s *PortalConn) PlayerName() string {
	return s.playerName
}

func (s *PortalConn) Online() bool {
	return s.online
}

func (s *PortalConn) RequestedHost() string {
	return s.requestedHost
}

func (s *PortalConn) Destination() string {
	return s.destination
}

func (s *PortalConn) ProtocolVersion() ProtocolVersion {
	return s.protocolVersion
}

type ConnectionListener interface {
	// setup cookies here
	OnTransfer(conn *PortalConn, target string)
	OnAuthentication(conn *PortalConn, enterLimbo func() error, transfer func() error) error
	OnLimboJoin(conn *PortalConn) error
	OnPlayerReady(conn *PortalConn) error
	OnPlayerChat(conn *PortalConn, message string)
	OnYggdrasilChallenge(conn *PortalConn, playerName string, clientSuggestedId uuid.UUID, privateKey *rsa.PrivateKey) (*Resp, error)

	OnStateTransition(conn *PortalConn, newState int)
	OnDisconnect(conn *PortalConn)
}

func (c *PortalConn) SetupListener(l ConnectionListener) {
	c.listener = l
}

func (c *PortalConn) Listener() ConnectionListener {
	return c.listener
}

func (c *PortalConn) State() int {
	return c.state
}

func (c *PortalConn) Context() context.Context {
	return c.ctx
}

func (c *PortalConn) Connection() *net.Conn {
	return c.conn
}

type StubListener int

func (s StubListener) OnYggdrasilChallenge(conn *PortalConn, playerName string, clientSuggestion uuid.UUID, privateKey *rsa.PrivateKey) (*Resp, error) {
	return Encrypt(conn.conn, playerName, privateKey, true, "https://sessionserver.mojang.com/")
}

func (s StubListener) OnNewConnection(conn *PortalConn) bool {
	return true
}

func (s StubListener) OnDisconnect(conn *PortalConn) {
}

func (s StubListener) OnTransfer(conn *PortalConn, target string) {

}

func (s StubListener) OnAuthentication(conn *PortalConn, enterLimbo func() error, transfer func() error) error {
	return transfer()
}

func (s StubListener) OnLimboJoin(conn *PortalConn) error {
	return nil

}
func (s StubListener) OnPlayerReady(conn *PortalConn) error {
	return nil
}

func (s StubListener) OnPlayerChat(conn *PortalConn, message string) {
}

func (s StubListener) OnStateTransition(conn *PortalConn, newState int) {

}
