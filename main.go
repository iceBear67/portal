package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Tnze/go-mc/chat"
	"github.com/Tnze/go-mc/data/packetid"
	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/Tnze/go-mc/offline"
	"github.com/Tnze/go-mc/yggdrasil/user"
	"github.com/goccy/go-yaml"
	"github.com/google/uuid"
)

type PlayerSample struct {
	Name string    `json:"name" yaml:"name"`
	ID   uuid.UUID `json:"id" yaml:"id"`
}

type ServerVersion struct {
	Name     string `json:"name" yaml:"name"`
	Protocol int    `json:"protocol" yaml:"protocol"`
}

type PlayerList struct {
	Max    int            `json:"max" yaml:"max"`
	Online int            `json:"online" yaml:"online"`
	Sample []PlayerSample `json:"sample" yaml:"sample"`
}

type ServerListPing struct {
	Version     ServerVersion `json:"version" yaml:"version"`
	Players     PlayerList    `json:"players" yaml:"players"`
	Description chat.Message  `json:"description" yaml:"description"`
	FavIcon     string        `json:"favicon,omitempty" yaml:"favicon,omitempty"`
}

type PortalConfig struct {
	Listen         string            `yaml:"listen"`
	FallbackServer string            `yaml:"fallback_server"`
	Servers        map[string]string `yaml:"servers"`
	DefaultInfo    ServerListPing    `yaml:"default_info"`
	DefaultSkin    string            `yaml:"default_skin"`
}

type Server struct {
	config     PortalConfig
	cachedInfo map[string]*ServerListPing
	stopped    bool
	privateKey *rsa.PrivateKey
}

type PortalConn struct {
	server          *Server
	player          *uuid.UUID
	state           int
	serverHost      string
	destination     string
	protocolVersion int
	conn            *net.Conn
	online          bool
}

func unwrap[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

var registryData []byte

func main() {
	config := &PortalConfig{
		Listen:  ":25565",
		Servers: make(map[string]string),
		DefaultInfo: ServerListPing{
			Version: ServerVersion{
				Name:     "Innocent Minecraft Server",
				Protocol: 0,
			},
			Players: PlayerList{
				Max:    0,
				Online: 0,
				Sample: make([]PlayerSample, 0),
			},
			Description: chat.Text("Not a minecraft server"),
			FavIcon:     "",
		},
		DefaultSkin: "e3RleHR1cmVzOntTS0lOOnt1cmw6Imh0dHA6Ly90ZXh0dXJlcy5taW5lY3JhZnQubmV0L3RleHR1cmUvODM3NmI4Y2RjZDUzM2YyNWI5NDlkOWU0MDYxYzM5ZDBlNWNjNTI2ZmJkYTBkZDBkMmI0YjVmNzgzZjIyMjJkZiJ9fX0=",
	}
	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
		bytes := unwrap(yaml.Marshal(config))
		os.WriteFile("config.yaml", bytes, 0600)
		log.Println("Default configuration has been created.")
	} else {
		err := yaml.Unmarshal(unwrap(os.ReadFile("config.yaml")), config)
		if err != nil {
			panic(err)
		}
	}
	if config.Servers == nil {
		panic("No servers configured")
	}
	if config.FallbackServer != "" {
		if _, ok := config.Servers[config.FallbackServer]; !ok {
			panic("Fallback server does not exist")
		}
	}
	log.Println("Loading registry data...")
	registryData = unwrap(os.ReadFile("registry_dump.bin"))
	serv := &Server{config: *config, stopped: false, cachedInfo: make(map[string]*ServerListPing)}
	log.Println("Generating keypair...")
	serv.privateKey = unwrap(rsa.GenerateKey(rand.Reader, 1024))
	log.Println("Harvesting remote server information...")
	serv.harvestServerInfo()
	go func() {
		ticker := time.NewTicker(time.Second * 30)
		for range ticker.C {
			serv.harvestServerInfo()
		}
	}()
	log.Println("Starting server on ", config.Listen)
	serv.Start()
}

func (s *Server) Start() {
	l := unwrap(net.ListenMC(s.config.Listen))
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.stopped {
				break
			}
			panic(err)
		}
		pc := PortalConn{
			server:          s,
			serverHost:      "",
			protocolVersion: 0,
			conn:            &conn,
		}
		go pc.handleConn()
	}
}

const (
	stateHandshake     = 0
	stateStatus        = 1
	stateLogin         = 2
	stateConfiguration = 3
	stateWaitTransfer  = -2
	stateExit          = -1
	statePlay          = 4
)

func (s *PortalConn) handleConn() {
	pkt := pk.Packet{} //todo clean idle connections
	idleTimeout := 2 * time.Minute
	go func() {
		timer := time.NewTimer(idleTimeout)
		defer timer.Stop()
		<-timer.C
		log.Println("Closing connection due to idle timeout:", *s.conn)
		s.conn.Close()
	}()
	defer s.conn.Close()
	for {
		err := s.conn.ReadPacket(&pkt)
		if err != nil {
			log.Println("Error reading packet at handleConn:", err, *s.conn)
			return
		}
		switch s.state {
		case stateHandshake:
			err = s.handleHandshake(&pkt)
		case stateStatus:
			err = s.handleStatus(&pkt)
		case stateLogin:
			err = s.handleLogin(&pkt)
		case stateConfiguration:
			err = s.handleConfig(&pkt)
		case statePlay:
			err = s.handlePlay(&pkt)
		case stateWaitTransfer:
		}
		if err != nil {
			log.Println("Error handling packet:", err)
			return
		}
		if s.state == stateExit {
			return
		}
	}
}

func (s *PortalConn) handleHandshake(pkt *pk.Packet) error {
	if pkt.ID == 0x00 {
		if s.protocolVersion != 0 {
			return fmt.Errorf("handshake Intent fired twice")
		}
		var (
			Protocol, Intent pk.VarInt
			ServerAddress    pk.String        // ignored
			Port             pk.UnsignedShort // ignored
		)
		err := pkt.Scan(&Protocol, &ServerAddress, &Port, &Intent)
		if err != nil {
			return err
		}
		s.protocolVersion = int(Protocol)
		s.serverHost = string(ServerAddress)
		switch Intent {
		case pk.VarInt(1):
			s.state = stateStatus
		case pk.VarInt(2):
			s.state = stateLogin
		case pk.VarInt(3): // todo transfer
			return fmt.Errorf("transfer intent not supported")
		}
		return nil
	}
	return fmt.Errorf("unexpected handshake packet %v", pkt.ID)
}

func (s *PortalConn) handleStatus(pkt *pk.Packet) error {
	switch pkt.ID {
	case packetid.StatusRequest:
		val, ok := s.server.cachedInfo[s.serverHost]
		if !ok {
			val = &s.server.config.DefaultInfo
			log.Println("Client ", *s.conn, " is requesting MOTD from a non-existent server \""+s.serverHost+"\"")
		}
		return s.sendStatusResponse(val)
	case packetid.StatusPingRequest: // PING
		s.state = stateExit
		return s.sendPingResponse(pkt)
	}
	return fmt.Errorf("unexpected status packet %v", pkt.ID)
}

func (s *PortalConn) handleLogin(p *pk.Packet) error {
	// the login flow is a fixed flow, so we just continue and go straight to config
	// read LoginStart
	if p.ID != packetid.LoginStart {
		return fmt.Errorf("unexpected packet %v", p.ID)
	}
	// check host and destination, otherwise reject.
	fallback := s.server.config.FallbackServer
	if s.serverHost == "" && fallback != "" {
		s.destination = fallback
	}
	destination, ok := s.server.config.Servers[s.serverHost]
	if !ok {
		// i18n
		_ = s.sendDisconnect(chat.Text("Hey! A valid server address must be provided.\n Please check the server IP carefully!"))
		return fmt.Errorf("disconnected for unknown destination")
	}
	s.destination = destination
	var (
		playerName pk.String
		UUID       pk.UUID // unused
	)
	if err := p.Scan(&playerName, &UUID); err != nil {
		return err
	}
	var id = offline.NameToUUID(string(playerName))
	online := id != uuid.UUID(UUID)
	s.online = online
	log.Println("Challenging", playerName, "with connection encryption")
	// Try to authenticate with Mojang
	var resp *Resp
	var err error
	if resp, err = Encrypt(s.conn, string(playerName), s.server.privateKey, online); err != nil {
		return err
	}
	if !online {
		resp.Properties = append(resp.Properties, user.Property{Name: "textures", Value: s.server.config.DefaultSkin})
	}
	id = resp.ID
	s.player = &id
	err = s.sendLoginSuccess(pk.UUID(id), playerName, resp.Properties, false)
	if err != nil {
		return err
	}

	log.Println("Player", playerName, "has logged in.")
	s.state = stateConfiguration
	return nil
}

func (s *PortalConn) handleConfig(pkt *pk.Packet) error {
	if pkt.ID != 0x03 {
		return fmt.Errorf("expect login_acknowledged but got %v", pkt.ID)
	}
	if !s.online {
		// jump to validation
		s.state = statePlay
		s.conn.WritePacket(pk.Marshal(0x01, pk.String("minecraft:brand"), pk.String("portal")))
		go s.keepalive()
		s.conn.Write(registryData)
		return s.sendFinishConfiguration()
	}
	// now transfer with cookies
	if err := s.goTransfer(s.destination); err != nil {
		return err
	}
	return s.sendFinishConfiguration()
}

func (s *PortalConn) goTransfer(serverAddr string) error {
	// set cookies...todo
	split := strings.Split(serverAddr, ":")
	if len(split) != 2 {
		return fmt.Errorf("invalid server address, expect host:port %v", serverAddr)
	}
	port, err := strconv.Atoi(split[1])
	if err != nil {
		return err
	}
	if err := s.sendTransfer(split[0], port); err != nil {
		return err
	}
	s.state = stateWaitTransfer
	return nil
}

func (s *PortalConn) handlePlay(pkt *pk.Packet) error {
	if pkt.ID == 0x03 { // finish configuration
		s.conn.WritePacket(pk.Marshal(0x2b,
			pk.Int(114514),
			pk.Boolean(false),
			pk.Array([]pk.Identifier{"minecraft:overworld"}),
			pk.VarInt(1),
			pk.VarInt(2),
			pk.VarInt(2),
			pk.Boolean(false),
			pk.Boolean(false),
			pk.Boolean(false),
			pk.VarInt(1), // dimension type
			pk.Identifier("minecraft:overworld"),
			pk.Long(-1145141919810),
			pk.UnsignedByte(3),
			pk.Byte(-1),
			pk.Boolean(false),
			pk.Boolean(false),
			pk.Boolean(false), // has no death location
			pk.VarInt(0),
			pk.VarInt(0),
			pk.Boolean(false),
		))
		s.conn.WritePacket(pk.Marshal(0x22, pk.UnsignedByte(13), pk.Float(0))) // gameevent 13
		s.conn.WritePacket(BuildEmptyChunkPacket(0, 0))
		s.conn.WritePacket(pk.Marshal(0x41, pk.VarInt(1919), // Synchronize position
			pk.Double(0),  //X
			pk.Double(70), //Y
			pk.Double(0),  //Z
			pk.Double(0),  //vX
			pk.Double(0),  //vY
			pk.Double(0),  //vZ
			pk.Float(0),   // yaw
			pk.Float(0),   // pitch
			pk.Int(0),
		))
	}
	return nil
}

func (s *PortalConn) keepalive() {
	ticker := time.NewTicker(time.Second * 15)
	defer ticker.Stop()
	for range ticker.C {
		pktId := 0x26
		if s.state == stateConfiguration {
			pktId = 0x04
		}
		err := s.conn.WritePacket(pk.Marshal(pktId, pk.Long(time.Now().UnixNano()/1e6)))
		if err != nil {
			log.Println("Error sending keepalive:", err)
			return
		}
	}
}

func (s *Server) harvestServerInfo() {
	for name, addr := range s.config.Servers {
		conn, err := net.DialMCTimeout(addr, time.Second)
		if err != nil {
			log.Println("Error connecting to server", name, err)
			continue
		}
		arr := strings.Split(addr, ":")
		port := unwrap(strconv.Atoi(arr[1]))
		err = sendHandshakePacket(conn, 0, arr[0], port, 1)
		if err != nil {
			log.Println("Error sending packet to server", name, err)
			conn.Close()
			continue
		}
		err = sendStatusRequest(conn)
		if err != nil {
			log.Println("Error sending status request to server", name, err)
			conn.Close()
			continue
		}
		pkt := pk.Packet{}
		err = conn.ReadPacket(&pkt)
		conn.Close()
		if err != nil {
			log.Println("Error reading packet when harvesting serverinfo:", err)
			continue
		}
		if pkt.ID != 00 {
			log.Println("Unexpected packet ID while fetching status:", pkt.ID)
			continue
		}
		var str pk.String
		err = pkt.Scan(&str)
		if err != nil {
			log.Println("Error scanning server info:", err)
			continue
		}
		var slp = ServerListPing{}
		err = json.Unmarshal([]byte(str), &slp)
		if err != nil {
			log.Println("Error unmarshaling server list ping:", err)
			continue
		}
		s.cachedInfo[name] = &slp
	}
}
