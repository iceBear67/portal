package limbo

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"maps"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/Tnze/go-mc/chat"
	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/Tnze/go-mc/offline"
	"github.com/Tnze/go-mc/yggdrasil/user"
	"github.com/go-mc/server/limbo/slp"
	"github.com/google/uuid"
	"github.com/icebear67/mfp-go"
	"github.com/patrickmn/go-cache"
	"github.com/werbenhu/eventbus"
)

type ProtocolVersion int

type Server struct {
	Config        *PortalConfig
	cachedInfo    *cache.Cache
	PrivateKey    *rsa.PrivateKey
	Known         *mfp.KeySet
	Identity      *mfp.Identity
	registryMap   *RegistryMap
	eventBus      *eventbus.EventBus
	eventListener EventListenerHost
	ctx           context.Context
	connCounter   atomic.Uint64
}

func (s *Server) Ctx() context.Context {
	return s.ctx
}

type EventListenerHost interface {
	OnNewConnection(conn *PortalConn) bool
	OnDisconnect(conn *PortalConn)
}

const (
	StateHandshake = 0
	StateLogin     = 1
	StateStatus    = 2
	StateConfig    = 3
	StatePlay      = 4
)

func NewServer(config *PortalConfig, registry *RegistryMap, ctx context.Context) (*Server, error) {
	log.Println("Generating keypair...")
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	keys := make([]mfp.PublicKey, 0, len(config.Servers))
	for i := range maps.Values(config.Servers) {
		keys = append(keys, mfp.PublicKey(i.PublicKey))
	}
	keySet := mfp.NewKeySet(keys...)
	server := &Server{
		Config:        config,
		Known:         keySet,
		Identity:      &mfp.Identity{PrivateKey: ed25519.PrivateKey(config.PrivateKey)},
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
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.feedRemoteStatus()
			case <-s.ctx.Done():
				return
			}
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
			id:              s.connCounter.Add(1),
			requestedHost:   "",
			protocolVersion: 0,
			state:           StateHandshake,
			conn:            &conn,
			listener:        StubListener(1),
		}
		allow := s.eventListener.OnNewConnection(&pc)
		if !allow {
			continue
		}
		go func() {
			defer s.eventListener.OnDisconnect(&pc)
			err := pc.startLoginSequence(s.Config.AuthTimeout, s.Config.StatusTimeout)
			if err != nil {
				pc.Logf("connection closed: %v", err)
			}
		}()
	}
}

func (s *Server) SetupListener(listener EventListenerHost) {
	s.eventListener = listener
}

// Handshake "next state" (intent) values.
const (
	intentStatus = 1
	intentLogin  = 2
	intentRTDP   = 127
)

func (s *PortalConn) startLoginSequence(authTimeout, statusTimeout time.Duration) error {
	// Bound the handshake read itself with the (short) status timeout so idle
	// sockets that never send a handshake cannot linger for the full auth
	// timeout. The deadline is cleared once we know the intent.
	_ = s.conn.Socket.SetReadDeadline(time.Now().Add(statusTimeout))
	intent, err := s.readHandshake()
	_ = s.conn.Socket.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}

	var (
		ctx context.Context
		fn  context.CancelFunc
	)
	if intent == pk.VarInt(intentRTDP) {
		// RTDP peer sessions are long-lived server-to-server links; they get no
		// timeout, only cancellation when the server shuts down.
		ctx, fn = context.WithCancel(s.server.ctx)
	} else {
		// Status pings are cheap and frequent; they get a much shorter budget
		// than the interactive login/auth flow.
		timeout := authTimeout
		if intent == pk.VarInt(intentStatus) {
			timeout = statusTimeout
		}
		ctx, fn = context.WithTimeout(context.Background(), timeout)
	}
	s.ctx = ctx
	go func() {
		<-ctx.Done()
		if !errors.Is(ctx.Err(), context.Canceled) {
			s.Logf("connection timed out")
		}
		s.conn.Close()
	}()
	defer fn()
	return s.dispatch(intent)
}

func (s *Server) feedRemoteStatus() {
	ctx := s.ctx
	for name, addr := range s.Config.Servers {
		result, err := HarvestStatus(addr, ctx, 3*time.Second)
		if err != nil {
			log.Printf("Error getting server status from %v: %v", name, err)
			continue
		}
		s.cachedInfo.SetDefault(name, result)
	}
}

// readHandshake reads the handshake packet, populating protocolVersion and
// requestedHost, and returns the client's requested next-state (intent).
func (s *PortalConn) readHandshake() (pk.VarInt, error) {
	var pkt pk.Packet
	err := s.conn.ReadPacket(&pkt)
	if err != nil {
		s.Logf("could not read handshake: %v", err)
		return 0, err
	}
	if pkt.ID != 0x00 {
		return 0, fmt.Errorf("unexpected handshake packet %v", pkt.ID)
	}
	var (
		Protocol, Intent pk.VarInt
		ServerAddress    pk.String        // ignored
		Port             pk.UnsignedShort // ignored
	)
	if err = pkt.Scan(&Protocol, &ServerAddress, &Port, &Intent); err != nil {
		return 0, err
	}
	s.protocolVersion = ProtocolVersion(Protocol)
	s.requestedHost = string(ServerAddress)
	return Intent, nil
}

func (s *PortalConn) dispatch(intent pk.VarInt) error {
	switch intent {
	case pk.VarInt(intentStatus):
		return s.handleStatus()
	case pk.VarInt(intentLogin):
		return s.handleLogin()
	case pk.VarInt(intentRTDP):
		return s.handleRtdpQuery()
	default: // todo transfer
		return fmt.Errorf("transfer intent not supported")
	}
}

func (s *PortalConn) handleStatus() error {
	s.listener.OnStateTransition(s, StateStatus)
	s.state = StateStatus
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
			info := &s.server.Config.DefaultInfo
			if name, _, ok := s.server.Config.MatchServer(s.requestedHost); ok {
				if cached, ok := s.server.cachedInfo.Get(name); ok {
					info = cached.(*slp.ServerListPing)
				} else {
					s.Logf("no cached status yet for server %q (host %q)", name, s.requestedHost)
				}
			} else {
				s.Logf("requesting status for a non-existent server %q", s.requestedHost)
			}
			err = s.sendStatusResponse(info)
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

var playerNamePattern = regexp.MustCompile("^[A-Za-z0-9_]{3,16}$")

func (s *PortalConn) handleLogin() error {
	s.listener.OnStateTransition(s, StateLogin)
	s.state = StateLogin
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
	_, destination, ok := s.server.Config.MatchServer(s.requestedHost)
	s.destination = destination
	if !ok {
		fallbackServer, ok := s.server.Config.Servers[fallback]
		if fallback != "" {
			if !ok {
				return fmt.Errorf("fallback-server refer to a non-existent server.")
			}
			s.destination = fallbackServer
		} else {
			// todo i18n
			_ = s.SendDisconnect(chat.Text("Hey! A valid server address must be provided.\n Please check the server IP carefully!"))
			return fmt.Errorf("disconnected for unknown destination")
		}
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
	if !playerNamePattern.MatchString(s.playerName) {
		return fmt.Errorf("invalid player name '%v'", s.playerName)
	}
	var theoryOfflineId = offline.NameToUUID(string(playerName))
	s.online = theoryOfflineId != uuid.UUID(clientSuggestId)
	if err = s.listener.OnServerNameIndicated(s, s.requestedHost); err != nil {
		return err
	}
	// Try to authenticate with Mojang
	if s.online {
		s.Logf("authenticating %v with yggdrasil...", playerName)
		var resp *Resp
		if resp, err = s.listener.OnYggdrasilChallenge(s, string(playerName), uuid.UUID(clientSuggestId), s.server.PrivateKey); err != nil {
			return err
		}
		s.playerId = &resp.ID
		err = s.sendLoginSuccess(pk.UUID(resp.ID), playerName, resp.Properties, false)
		if err != nil {
			return err
		}
		s.Logf("authenticated by Yggdrasil")
	} else {
		prop := []user.Property{{Name: "textures", Value: s.server.Config.DefaultSkin}}
		s.playerId = &theoryOfflineId
		err = s.sendLoginSuccess(pk.UUID(theoryOfflineId), playerName, prop, true)
		if err != nil {
			return err
		}
		s.Logf("joined in offline mode")
	}
	return s.handleConfiguration()
}

func (s *PortalConn) handleConfiguration() error {
	s.listener.OnStateTransition(s, StateConfig)
	s.state = StateConfig
	var pkt pk.Packet
	err := s.conn.ReadPacket(&pkt)
	if err != nil {
		return err
	}
	if int(pkt.ID) != s.protocolVersion.LoginAcknowledged() {
		return fmt.Errorf("expect login_acknowledged but got %v", pkt.ID)
	}
	go s.runKeepAlive(s.server.Config.Keepalive)

	setupLimbo := func() error {
		// start limbo authentication
		err = s.sendBrand("portal")
		if err != nil {
			return err
		}
		data, ok := s.server.registryMap.Next(s.protocolVersion)
		if !ok {
			return fmt.Errorf("no registry data found for protocol version %v", s.protocolVersion)
		}
		s.writeMu.Lock()
		_, err = s.conn.Write(data.Value())
		s.writeMu.Unlock()
		if err != nil {
			return err
		}
		err = s.sendFinishConfiguration()
		if err != nil {
			return err
		}
		return s.handlePlay() // transition to play state
	}
	goTransfer := func() error {
		if err := s.TransferDestination(); err != nil {
			return err
		}
		return s.sendFinishConfiguration()
	}
	err = s.listener.OnAuthentication(s, setupLimbo, goTransfer)
	if err != nil {
		s.Logf("authentication failed: %v", err)
		s.SendDisconnect(chat.Text("Access denied\n\nAn internal error has occurred, please contact the administrator for help. "))
		return err
	}
	return nil
}

func (s *PortalConn) handlePlay() error {
	s.listener.OnStateTransition(s, StatePlay)
	s.state = StatePlay
	return s.handlePlayInitialization()
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
			err = s.listener.OnLimboJoin(s)
			if err != nil {
				return err
			}
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
			s.Logf("player %v has joined", s.playerId)
			err = s.listener.OnPlayerReady(s) //todo log
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}
