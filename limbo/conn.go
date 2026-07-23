package limbo

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"sync"

	"github.com/Tnze/go-mc/net"
	"github.com/google/uuid"
	"github.com/icebear67/mfp-go/pip"
	"github.com/icebear67/mfp-go/rtdp"
)

type PortalConn struct {
	server *Server
	// monotonic per-server connection id, used to correlate log lines.
	id uint64
	// not valid until login success
	playerId   *uuid.UUID
	playerName string
	online     bool

	// initialized with StateHandshake
	state int

	// not valid until handshake complete
	requestedHost   string
	destination     *ServerConfig
	protocolVersion ProtocolVersion

	// always available
	conn     *net.Conn
	ctx      context.Context
	listener ConnectionListener

	// serializes all writes to conn; keepalive runs on its own goroutine
	// concurrently with the main handler, and go-mc's net.Conn is not
	// write-safe (a shared CFB8 stream cipher would corrupt otherwise).
	writeMu sync.Mutex

	// prevent multiple disconnection (guarded by writeMu)
	_disconnected bool
}

// Id returns the connection's monotonic id.
func (s *PortalConn) Id() uint64 { return s.id }

// String renders a stable connection tag for logging.
func (s *PortalConn) String() string {
	addr := "?"
	if s.conn != nil && s.conn.Socket != nil {
		addr = s.conn.Socket.RemoteAddr().String()
	}
	if s.playerName != "" {
		return fmt.Sprintf("conn#%d %s %s", s.id, addr, s.playerName)
	}
	return fmt.Sprintf("conn#%d %s", s.id, addr)
}

// Logf writes a connection-scoped log line prefixed with [String()].
func (s *PortalConn) Logf(format string, args ...any) {
	log.Printf("["+s.String()+"] "+format, args...)
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

func (s *PortalConn) IsUserOnline() bool {
	return s.online
}

func (s *PortalConn) RequestedHost() string {
	return s.requestedHost
}

func (s *PortalConn) Destination() *ServerConfig {
	return s.destination
}

func (s *PortalConn) ProtocolVersion() ProtocolVersion {
	return s.protocolVersion
}

type ConnectionListener interface {
	Init(conn *PortalConn) error
	// OnTransfer sets up cookies before the transfer packet is sent. Returning
	// an error aborts the transfer (the caller will not send the packet).
	OnTransfer(conn *PortalConn, target string, port int) error
	OnAuthentication(conn *PortalConn, enterLimbo func() error, transfer func() error) error
	OnLimboJoin(conn *PortalConn) error
	OnPlayerReady(conn *PortalConn) error
	OnPlayerChat(conn *PortalConn, message string)
	OnYggdrasilChallenge(conn *PortalConn, playerName string, clientSuggestedId uuid.UUID, privateKey *rsa.PrivateKey) (*Resp, error)
	OnServerNameIndicated(conn *PortalConn, serverName string) error

	OnStateTransition(conn *PortalConn, newState int)
	OnDisconnect(conn *PortalConn)
}

func (c *PortalConn) SetupListener(l ConnectionListener) {
	if err := l.Init(c); err != nil {
		log.Println("Failed to init connection listener", l, ":", err)
		return
	}
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

func (s *PortalConn) handleRtdpQuery() error {
	session, err := rtdp.Accept(s.conn, rtdp.Config{
		Identity: s.server.Identity,
		Known:    s.server.Known,
	})
	if err != nil {
		return err
	}
	for {
		arrived, err := session.ReadPacket()
		if err != nil {
			return err
		}
		if p, ok := arrived.(*rtdp.PeerPayload); ok && p.Action == pip.ActionArrive {
			err = session.Acknowledge(p.TransactionID, "")
			if err != nil {
				return err
			}
		}
	}
}

type StubListener int

func (s StubListener) Init(conn *PortalConn) error {
	return nil
}

func (s StubListener) OnServerNameIndicated(conn *PortalConn, serverName string) error {
	return nil
}

func (s StubListener) OnYggdrasilChallenge(conn *PortalConn, playerName string, clientSuggestion uuid.UUID, privateKey *rsa.PrivateKey) (*Resp, error) {
	return Encrypt(conn.conn, playerName, privateKey, true, "https://sessionserver.mojang.com/")
}

func (s StubListener) OnNewConnection(conn *PortalConn) bool {
	return true
}

func (s StubListener) OnDisconnect(conn *PortalConn) {
}

func (s StubListener) OnTransfer(conn *PortalConn, target string, port int) error {
	return nil
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
