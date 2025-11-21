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
		os.WriteFile("config.yaml", bytes, 0644)
		log.Println("Default configuration has been created.")
	} else {
		err := yaml.Unmarshal(unwrap(os.ReadFile("config.yaml")), config)
		if err != nil {
			panic(err)
		}
	}
	if config.FallbackServer != "" {
		if _, ok := config.Servers[config.FallbackServer]; !ok {
			panic("Fallback server does not exist")
		}
	}
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
	pkt := pk.Packet{}
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
		case stateWaitTransfer:
			continue
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
			s.state = stateConfiguration
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
		str, err := json.Marshal(val)
		if err != nil {
			return err
		}
		return s.conn.WritePacket(pk.Marshal(0x00, pk.String(str)))
	case packetid.StatusPingRequest: // PING
		s.state = stateExit
		return s.conn.WritePacket(*pkt)
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
		disconnectMsg, _ := json.Marshal(chat.Text("Hey! A valid server address must be provided.\n Please check the server IP carefully!"))
		_ = s.conn.WritePacket(pk.Marshal(0x00, pk.String(disconnectMsg)))
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
	if id == uuid.UUID(UUID) {
		log.Println("UUID of player", playerName, "suggests they are offline.")
		var props []user.Property
		props = append(props, user.Property{Name: "textures", Value: s.server.config.DefaultSkin})
		if err := s.conn.WritePacket(pk.Marshal(int(packetid.LoginSuccess), UUID, playerName, pk.Array(props), pk.Boolean(false))); err != nil {
			return err
		}
	} else {
		log.Println("Challenging", playerName, "with connection encryption")
		// Try to authenticate with Mojang
		var resp *Resp
		var err error
		if resp, err = Encrypt(s.conn, string(playerName), s.server.privateKey); err != nil {
			return err
		}
		id = resp.ID
		err = s.conn.WritePacket(pk.Marshal(
			int(packetid.LoginSuccess),
			pk.UUID(id), playerName, pk.Array(resp.Properties)))
		if err != nil {
			return err
		}
		s.online = true
	}
	log.Println("Player", playerName, "has logged in.")
	s.state = stateConfiguration
	return nil
}

func (s *PortalConn) handleConfig(pkt *pk.Packet) error {
	if pkt.ID != 0x03 {
		return fmt.Errorf("expect login_acknowledged but got %v", pkt.ID)
	}
	if s.online {
		// direct transfer, no more validation.

	}
	// send a keep alive to prevent disconnection, within 30s.
	//if err := s.conn.WritePacket(pk.Marshal(packetid.ClientboundKeepAlive, pk.Long(0))); err != nil {
	//	return err
	//}
	//if err := s.conn.ReadPacket(pkt); err != nil {
	//	return err
	//}
	//if pkt.ID != int32(packetid.ServerboundKeepAlive) {
	//	return fmt.Errorf("expect keepalive but got %v", pkt.ID)
	//}
	// now transfer with cookies
	if err := s.goTransfer(s.destination); err != nil {
		return err
	}
	return s.conn.WritePacket(pk.Marshal(0x03)) // finish configuration.
}

func (s *PortalConn) goTransfer(serverAddr string) error {
	// set cookies...todo
	packetId := 0
	if s.state == stateConfiguration {
		packetId = 0x0B
	} else {
		packetId = 0x7A
	}
	split := strings.Split(serverAddr, ":")
	if len(split) != 2 {
		return fmt.Errorf("invalid server address, expect host:port %v", serverAddr)
	}
	port, err := strconv.Atoi(split[1])
	if err != nil {
		return err
	}
	if err := s.conn.WritePacket(pk.Marshal(packetId, pk.String(split[0]), pk.VarInt(port))); err != nil {
		return err
	}
	s.state = stateWaitTransfer
	return nil
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
		err = conn.WritePacket(pk.Marshal(0x00, pk.VarInt(0), pk.String(arr[0]), pk.UnsignedShort(port), pk.VarInt(1)))
		if err != nil {
			log.Println("Error sending packet to server", name, err)
			continue
		}
		conn.WritePacket(pk.Marshal(0x00))
		pkt := pk.Packet{}
		err = conn.ReadPacket(&pkt)
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
