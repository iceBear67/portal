package main

import (
	"encoding/hex"
	"flag"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
)

var target = flag.String("output", "mitm_dump.nbt", "Output NBT file path")
var server = flag.String("server", "link.star-dust.link:25565", "Target server address")
var listen = flag.String("listen", ":25565", "Listen address")

const (
	stateHandshake     = 0
	stateLogin         = 1
	stateConfiguration = 2
	statePlay          = 3
)

var buf *os.File

func main() {
	flag.Parse()
	var err error
	buf, err = os.OpenFile(*target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("failed to open output file %s: %v", *target, err)
	}
	defer func() {
		if err := buf.Close(); err != nil {
			log.Printf("failed to close output file: %v", err)
		}
	}()

	log.Printf("listening on %s, forwarding to %s, dumping to %s", *listen, *server, *target)
	l, err := net.ListenMC(*listen)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *listen, err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		log.Printf("accepted connection from %v", conn)
		go handle(conn)
	}
}

var state = 0

func handle(conn net.Conn) {

	log.Printf("connecting to upstream %s", *server)
	sconn, err := net.DialMC(*server)
	if err != nil {
		log.Printf("failed to connect to upstream %s: %v", *server, err)
		conn.Close()
		return
	}
	defer func() {
		conn.Close()
		sconn.Close()
	}()
	pkt := &pk.Packet{}
	serverLoop(conn, sconn)
	for {
		err = conn.ReadPacket(pkt)
		if err != nil {
			log.Printf("read packet from client %v error: %v", conn, err)
			return
		}
		log.Printf("received packet from client %v id=0x%x (state=%d)", conn, pkt.ID, state)
	se:
		switch state {
		case stateHandshake:
			if pkt.ID != 0x00 {
				log.Printf("unexpected packet in handshake state: id=0x%x", pkt.ID)
				return
			}
			var (
				Protocol      pk.VarInt
				ServerAddress pk.String        // ignored
				Port          pk.UnsignedShort // ignored
				Intent        pk.VarInt
			)
			err := pkt.Scan(&Protocol, &ServerAddress, &Port, &Intent)
			if err != nil {
				log.Printf("failed to scan handshake packet: %v", err)
				return
			}
			if Intent != 2 {
				log.Printf("client handshake intent is not 2 (login): %d, closing", Intent)
				break se
			}
			state = stateLogin
			log.Printf("handshake received: protocol=%d, intent=%d, transitioning to login", Protocol, Intent)
			split := strings.Split(*server, ":")
			ServerAddress = pk.String(split[0])
			if len(split) > 1 {
				if port, err := strconv.ParseUint(split[1], 10, 16); err == nil {
					Port = pk.UnsignedShort(port)
				}
			}
			if err := sconn.WritePacket(pk.Marshal(0x00, Protocol, ServerAddress, Port, Intent)); err != nil {
				log.Printf("failed to write modified handshake to server %s: %v", *server, err)
				return
			}
			continue
		}
		if err := sconn.WritePacket(*pkt); err != nil {
			log.Printf("write packet to server %s id=0x%x error: %v", *server, pkt.ID, err)
		}
	}
}

func serverLoop(conn net.Conn, sconn *net.Conn) {
	go func() {
		spkt := &pk.Packet{}
		for {
			err := sconn.ReadPacket(spkt)
			if err != nil {
				log.Printf("read packet from server %s error: %v", *server, err)
				return
			}
			log.Printf("received packet from server state:%v id=0x%x", state, spkt.ID)
			if err := conn.WritePacket(*spkt); err != nil {
				log.Printf("write packet to client %v id=0x%x error: %v", conn, spkt.ID, err)
				return
			}
			switch state {
			case stateLogin:
				switch spkt.ID { // set compression
				case 0x03:
					var threshold pk.VarInt
					spkt.Scan(&threshold)
					conn.SetThreshold(int(threshold))
					sconn.SetThreshold(int(threshold))
					log.Printf("set compression threshold to %d", int(threshold))
				case 0x02:
					state = (stateConfiguration)
					log.Printf("state changed to configuration")
				}
			case stateConfiguration:
				switch spkt.ID {
				case 0x03:
					log.Println("Configuration phase ended.")
					state = (statePlay)
					log.Println("state changed to play")
				case 0x07: // registry data
					log.Printf("saving registry packet id=0x%x to %s", spkt.ID, buf.Name())
					spkt.Pack(buf, 1000000000)
				}
			case statePlay:
				switch spkt.ID {
				case 0x2B:
					log.Println(hex.EncodeToString(spkt.Data))
					return
				}
			}
		}
	}()
}
