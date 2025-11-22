package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Tnze/go-mc/chat"
	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/Tnze/go-mc/offline"
	"github.com/Tnze/go-mc/yggdrasil/user"
	"github.com/go-mc/server/server/slp"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
)

type ProtocolVersion int

type Server struct {
	Config      *PortalConfig
	cachedInfo  *cache.Cache
	PrivateKey  *rsa.PrivateKey
	registryMap *RegistryMap
	ctx         context.Context
}

const (
	stateHandshake = 0
	stateLogin     = 1
	stateStatus    = 2
	stateConfig    = 3
	statePlay      = 4
)

type PortalConn struct {
	server          *Server
	player          *uuid.UUID
	state           int
	serverHost      string
	destination     string
	protocolVersion ProtocolVersion
	conn            *net.Conn
	online          bool
	ctx             context.Context
}

func NewServer(config *PortalConfig, registry *RegistryMap, ctx context.Context) (*Server, error) {
	log.Println("Generating keypair...")
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	server := &Server{
		Config:      config,
		cachedInfo:  cache.New(config.CacheInvalidate, 5*time.Second),
		ctx:         ctx,
		PrivateKey:  privKey,
		registryMap: registry,
	}
	return server, nil
}

func (s *Server) Start() error {
	l, err := net.ListenMC(s.Config.Listen)
	if err != nil {
		return err
	}
	stopped := false
	go func() {
		select {
		case <-s.ctx.Done():
			stopped = true
			_ = l.Close()
		}
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if stopped {
				return nil
			}
			log.Println("Error accepting connection:", err)
			continue
		}
		pc := PortalConn{
			server:          s,
			serverHost:      "",
			protocolVersion: 0,
			state:           stateHandshake,
			conn:            &conn,
		}
		go func() {
			err := pc.startLoginSequence(s.Config.AuthTimeout)
			if err != nil {
				log.Println("Error from connection", conn.Socket.RemoteAddr(), ":", err)
			}
		}()
	}
}

func (s *PortalConn) startLoginSequence(timeout time.Duration) error {
	ctx, fn := context.WithTimeout(context.Background(), timeout)
	go func() {
		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.Canceled) {
				log.Println("Authentication process timed out for connection", s)
			}
			s.conn.Close()
		}
	}()
	defer fn()
	return s.handleHandshake()
}

func (s *PortalConn) handleHandshake() error {
	var pkt pk.Packet
	err := s.conn.ReadPacket(&pkt)
	if err != nil {
		log.Println("could not read handshake from ", s)
		return err
	}
	if pkt.ID != 0x00 {
		return fmt.Errorf("unexpected handshake packet %v", pkt.ID)
	}
	var (
		Protocol, Intent pk.VarInt
		ServerAddress    pk.String        // ignored
		Port             pk.UnsignedShort // ignored
	)
	err = pkt.Scan(&Protocol, &ServerAddress, &Port, &Intent)
	if err != nil {
		return err
	}
	s.protocolVersion = ProtocolVersion(Protocol)
	s.serverHost = string(ServerAddress)
	switch Intent {
	case pk.VarInt(1):
		return s.handleStatus()
	case pk.VarInt(2):
		return s.handleLogin()
	default: // todo transfer
		return fmt.Errorf("transfer intent not supported")
	}
}

func (s *PortalConn) handleStatus() error {
	s.state = stateStatus
	var pkt pk.Packet
	pingAnswered := false
	statusAnswered := false
	for {
		if pingAnswered && statusAnswered {
			return nil
		}
		err := s.conn.ReadPacket(&pkt)
		if err != nil {
			return err
		}
		if pkt.ID != 0x00 && !statusAnswered {
			statusAnswered = true
			val, ok := s.server.cachedInfo.Get(s.serverHost)
			if !ok {
				val = &s.server.Config.DefaultInfo
				log.Println("client", s.conn.Socket.RemoteAddr(), "is requesting status for a non-existent server \""+s.serverHost+"\"")
			}
			err = s.sendStatusResponse(val.(*slp.ServerListPing))
			if err != nil {
				return err
			}
			continue
		} else if pkt.ID == 0x01 && !pingAnswered {
			pingAnswered = true
			err = s.sendPingResponse(&pkt)
			if err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("unexpected status packet %v", pkt.ID)
	}
}

func (s *PortalConn) handleLogin() error {
	s.state = stateLogin
	var pkt pk.Packet
	err := s.conn.ReadPacket(&pkt)
	if err != nil {
		return err
	}
	if pkt.ID != 0x00 {
		return fmt.Errorf("unexpected packet %v", pkt.ID)
	}
	// check host and destination, otherwise reject.
	fallback := s.server.Config.FallbackServer
	destination, ok := s.server.Config.Servers[s.serverHost]
	if !ok {
		if fallback != "" {
			s.destination = fallback
		} else {
			// todo i18n
			_ = s.sendDisconnect(chat.Text("Hey! A valid server address must be provided.\n Please check the server IP carefully!"))
			return fmt.Errorf("disconnected for unknown destination")
		}
	} else {
		s.destination = destination
	}
	var (
		playerName pk.String
		// usually, this is either a mojang uuid or an offline uuid
		clientSuggestId pk.UUID
	)
	if err := pkt.Scan(&playerName, &clientSuggestId); err != nil {
		return err
	}
	var theoryOfflineId = offline.NameToUUID(string(playerName))
	s.online = theoryOfflineId != uuid.UUID(clientSuggestId)
	if s.online {
		log.Println("Authenticating", playerName, "with connection encryption")
	}
	// Try to authenticate with Mojang
	if s.online {
		var resp *Resp
		if resp, err = Encrypt(s.conn, string(playerName), s.server.PrivateKey, s.online); err != nil {
			return err
		}
		s.player = &resp.ID
		err = s.sendLoginSuccess(pk.UUID(resp.ID), playerName, resp.Properties, false)
		if err != nil {
			return err
		}
		log.Println("Player", playerName, "has been authenticated by Yggdrasil.")
	} else {
		prop := []user.Property{{Name: "textures", Value: s.server.Config.DefaultSkin}}
		err = s.sendLoginSuccess(pk.UUID(theoryOfflineId), playerName, prop, true)
		if err != nil {
			return err
		}
		log.Println("Try authenticating", playerName, "with user/pass")
	}
	return s.handleConfiguration()
}

func (s *PortalConn) handleConfiguration() error {
	s.state = stateConfig
	var pkt pk.Packet
	err := s.conn.ReadPacket(&pkt)
	if err != nil {
		return err
	}
	if int(pkt.ID) != s.protocolVersion.LoginAcknowledged() {
		return fmt.Errorf("expect login_acknowledged but got %v", pkt.ID)
	}
	if s.online {
		if err := s.goTransfer(s.destination); err != nil {
			return err
		}
		return s.sendFinishConfiguration()
	}
	// start limbo authentication
	err = s.sendBrand("portal")
	if err != nil {
		return err
	}
	go s.runKeepAlive(s.server.Config.Keepalive)
	data, ok := s.server.registryMap.Next(s.protocolVersion)
	if !ok {
		return fmt.Errorf("no registry data found for protocol version %v", s.protocolVersion)
	}
	_, err = s.conn.Write(data.Value())
	if err != nil {
		return err
	}
	err = s.sendFinishConfiguration()
	if err != nil {
		return err
	}
	return s.handlePlay() // transition to play state
}

func (s *PortalConn) handlePlay() error {
	s.state = statePlay
	var pkt pk.Packet
	for {
		err := s.conn.ReadPacket(&pkt)
		if err != nil {
			return err
		}
		if int(pkt.ID) == s.protocolVersion.FinishConfiguration() { // finish configuration
			err = s.sendGameEvent13()
			err = s.sendEmptyChunk(0, 0)
			err = s.sendSynchronizePosition()
		}
	}
}

func (s *Server) feedRemoteStatus(ctx context.Context) {
	for name, addr := range s.Config.Servers {
		result, err := HarvestStatus(addr, ctx, 3*time.Second)
		if err != nil {
			log.Printf("Error getting server status from %v: %v", addr, err)
			continue
		}
		s.cachedInfo.SetDefault(name, result)
	}
}
