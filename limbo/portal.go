package limbo

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
	"github.com/go-mc/server/limbo/slp"
	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"github.com/werbenhu/eventbus"
)

type ProtocolVersion int

type Server struct {
	Config        *PortalConfig
	cachedInfo    *cache.Cache
	PrivateKey    *rsa.PrivateKey
	registryMap   *RegistryMap
	eventBus      *eventbus.EventBus
	eventListener EventListenerHost
	ctx           context.Context
}

type EventListenerHost interface {
	OnNewConnection(conn *PortalConn) bool
	OnDisconnect(conn *PortalConn)
}

const (
	stateHandshake = 0
	stateLogin     = 1
	stateStatus    = 2
	stateConfig    = 3
	statePlay      = 4
)

func NewServer(config *PortalConfig, registry *RegistryMap, ctx context.Context) (*Server, error) {
	log.Println("Generating keypair...")
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	server := &Server{
		Config:        config,
		cachedInfo:    cache.New(config.CacheInvalidate, 5*time.Second),
		ctx:           ctx,
		PrivateKey:    privKey,
		registryMap:   registry,
		eventBus:      eventbus.New(),
		eventListener: StubListener(0),
	}
	return server, nil
}

func (s *Server) EventBus() *eventbus.EventBus {
	return s.eventBus
}

func (s *Server) Start() error {
	l, err := net.ListenMC(s.Config.Listen)
	if err != nil {
		return err
	}
	stopped := false
	s.feedRemoteStatus()
	go func() {
		t := time.NewTicker(10 * time.Second)
		select {
		case <-t.C:
			s.feedRemoteStatus()
		}
	}()
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
			requestedHost:   "",
			protocolVersion: 0,
			state:           stateHandshake,
			conn:            &conn,
			listener:        StubListener(1),
		}
		allow := s.eventListener.OnNewConnection(&pc)
		if !allow {
			continue
		}
		go func() {
			defer s.eventListener.OnDisconnect(&pc)
			err := pc.startLoginSequence(s.Config.AuthTimeout)
			if err != nil {
				log.Println("Error from connection", conn.Socket.RemoteAddr(), ":", err)
			}
		}()
	}
}

func (s *Server) SetupListener(listener EventListenerHost) {
	s.eventListener = listener
}

func (s *PortalConn) startLoginSequence(timeout time.Duration) error {
	ctx, fn := context.WithTimeout(context.Background(), timeout)
	s.ctx = ctx
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

func (s *Server) feedRemoteStatus() {
	ctx := s.ctx
	for name, addr := range s.Config.Servers {
		result, err := HarvestStatus(addr, ctx, 3*time.Second)
		if err != nil {
			log.Printf("Error getting server status from %v: %v", addr, err)
			continue
		}
		s.cachedInfo.SetDefault(name, result)
	}
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
	s.requestedHost = string(ServerAddress)
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
	s.listener.OnStateTransition(s, stateStatus)
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
		if pkt.ID == 0x00 && !statusAnswered {
			statusAnswered = true
			val, ok := s.server.cachedInfo.Get(s.requestedHost)
			if !ok {
				val = &s.server.Config.DefaultInfo
				log.Println("client", s.conn.Socket.RemoteAddr(), "is requesting status for a non-existent server \""+s.requestedHost+"\"")
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
	s.listener.OnStateTransition(s, stateLogin)
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
	destination, ok := s.server.Config.Servers[s.requestedHost]
	if !ok {
		if fallback != "" {
			s.destination = fallback
		} else {
			// todo i18n
			_ = s.SendDisconnect(chat.Text("Hey! A valid server address must be provided.\n Please check the server IP carefully!"))
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
	s.playerName = string(playerName)
	var theoryOfflineId = offline.NameToUUID(string(playerName))
	s.online = theoryOfflineId != uuid.UUID(clientSuggestId)
	// Try to authenticate with Mojang
	if s.online {
		log.Println("Authenticating", playerName, "with connection encryption")
		var resp *Resp
		if resp, err = s.listener.OnYggdrasilChallenge(s, string(playerName), s.server.PrivateKey); err != nil {
			return err
		}
		s.playerId = &resp.ID
		err = s.sendLoginSuccess(pk.UUID(resp.ID), playerName, resp.Properties, false)
		if err != nil {
			return err
		}
		log.Println("Player", playerName, "has been authenticated by Yggdrasil.")
	} else {
		prop := []user.Property{{Name: "textures", Value: s.server.Config.DefaultSkin}}
		s.playerId = &theoryOfflineId
		err = s.sendLoginSuccess(pk.UUID(theoryOfflineId), playerName, prop, true)
		if err != nil {
			return err
		}
		log.Println("Try authenticating", playerName, "with user/pass")
	}
	return s.handleConfiguration()
}

func (s *PortalConn) handleConfiguration() error {
	s.listener.OnStateTransition(s, stateConfig)
	s.state = stateConfig
	var pkt pk.Packet
	err := s.conn.ReadPacket(&pkt)
	if err != nil {
		return err
	}
	if int(pkt.ID) != s.protocolVersion.LoginAcknowledged() {
		return fmt.Errorf("expect login_acknowledged but got %v", pkt.ID)
	}

	setupLimbo := s.listener.onAuthentication(s, s.online)
	if !setupLimbo {
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
	s.listener.OnStateTransition(s, statePlay)
	s.state = statePlay
	if err := s.handlePlayInitialization(); err != nil {
		return err
	}
	var pkt pk.Packet
	for {
		err := s.conn.ReadPacket(&pkt)
		if err != nil {
			return err
		}
		if int(pkt.ID) == s.protocolVersion.ChatMessage() {
			msg, err := s.ReadChatMessage(&pkt)
			if err != nil {
				return err
			}
			s.listener.OnPlayerChat(s, msg)
		}
	}
}

func (s *PortalConn) handlePlayInitialization() error {
	phase := 0
	var pkt pk.Packet
	for {
		err := s.conn.ReadPacket(&pkt)
		if err != nil {
			return err
		}
		if int(pkt.ID) == s.protocolVersion.FinishConfiguration() && phase == 0 { // finish configuration
			phase = 1
			s.listener.OnLimboJoin(s)
			err = s.sendLoginPlay()
			if err != nil {
				return err
			}
			err = s.sendGameEvent13()
			if err != nil {
				return err
			}
			err = s.sendEmptyChunk(0, 0)
			if err != nil {
				return err
			}
			err = s.sendSynchronizePosition()
			if err != nil {
				return err
			}
		} else if int(pkt.ID) == s.protocolVersion.PlayerLoadedJoin() && phase == 1 {
			phase = 2
			s.listener.OnPlayerReady(s)
			log.Println("Player", s.playerName+"/"+s.playerId.String(), "has joined.")
			break
		}
	}
	return nil
}
