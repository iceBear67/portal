package limbo

import (
	"context"

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
	onTransfer(conn *PortalConn, target string)
	onAuthentication(conn *PortalConn, online bool) (setupLimbo bool)
	onLimboJoin(conn *PortalConn)
	onPlayerReady(conn *PortalConn)
	onPlayerChat(conn *PortalConn, message string)

	onStateTransition(conn *PortalConn, newState int)
}

func (c *PortalConn) SetupListener(l ConnectionListener) {
	c.listener = l
}

func (c *PortalConn) State() int {
	return c.state
}

func (c *PortalConn) Context() context.Context {
	return c.ctx
}

type StubListener int

func (s StubListener) onNewConnection(conn *PortalConn) bool {
	return true
}

func (s StubListener) onDisconnect(conn *PortalConn) {
}

func (s StubListener) onTransfer(conn *PortalConn, target string) {

}

func (s StubListener) onAuthentication(conn *PortalConn, online bool) (setupLimbo bool) {
	return !online
}

func (s StubListener) onLimboJoin(conn *PortalConn) {

}
func (s StubListener) onPlayerReady(conn *PortalConn) {

}

func (s StubListener) onPlayerChat(conn *PortalConn, message string) {
}

func (s StubListener) onStateTransition(conn *PortalConn, newState int) {

}
