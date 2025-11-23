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

	// initialized with stateHandshake
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

type ConnectionListener interface {
	// setup cookies here
	OnTransfer(conn *PortalConn, target string)
	onAuthentication(conn *PortalConn, online bool) (setupLimbo bool)
	OnLimboJoin(conn *PortalConn)
	OnPlayerReady(conn *PortalConn)
	OnPlayerChat(conn *PortalConn, message string)
	OnYggdrasilChallenge(conn *PortalConn, playerName string, privateKey *rsa.PrivateKey) (*Resp, error)

	OnStateTransition(conn *PortalConn, newState int)
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

type StubListener int

func (s StubListener) OnYggdrasilChallenge(conn *PortalConn, playerName string, privateKey *rsa.PrivateKey) (*Resp, error) {
	return Encrypt(conn.conn, playerName, privateKey, true)
}

func (s StubListener) OnNewConnection(conn *PortalConn) bool {
	return true
}

func (s StubListener) OnDisconnect(conn *PortalConn) {
}

func (s StubListener) OnTransfer(conn *PortalConn, target string) {

}

func (s StubListener) onAuthentication(conn *PortalConn, online bool) (setupLimbo bool) {
	return !online
}

func (s StubListener) OnLimboJoin(conn *PortalConn) {

}
func (s StubListener) OnPlayerReady(conn *PortalConn) {

}

func (s StubListener) OnPlayerChat(conn *PortalConn, message string) {
}

func (s StubListener) OnStateTransition(conn *PortalConn, newState int) {

}
