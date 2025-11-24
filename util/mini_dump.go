package main

import (
	"flag"
	"log"
	"os"
	"sync/atomic"

	"github.com/Tnze/go-mc/data/packetid"
	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
)

var target = flag.String("output", "registry_dump.bin", "Output file path")
var server = flag.String("server", "link.star-dust.link", "Target server address")
var listen = flag.String("listen", ":25565", "Listen address")
var compress = flag.Int("threshold", -1, "compress threshold of the packets, -1 to disable")

const (
	stateHandshake     = 0
	stateStatusOrLogin = -1
	stateLogin         = 1
	stateConfiguration = 2
	statePlay          = 3
)

func main() {
	flag.Parse()
	l, err := net.ListenMC(*listen)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		serverConn, err := net.DialMC(*server)
		pipe := Pipe{
			clientConn: &conn,
			serverConn: serverConn,
			state:      atomic.Int32{},
		}
		go pipe.handleConn(conn)
	}
}

type Pipe struct {
	clientConn *net.Conn
	serverConn *net.Conn
	state      atomic.Int32
}

func (p *Pipe) handleConn(clientConn net.Conn) {
	log.Println("Handling new connection to", *server)
	p.state.Store(stateHandshake)
	clientPkt := pk.Packet{}
	go p.handleServerFwd()
	defer p.clientConn.Close()
	defer p.serverConn.Close()
	for {
		err := clientConn.ReadPacket(&clientPkt)
		if err != nil {
			log.Println("error reading from client:", err)
			return
		}
		err = p.serverConn.WritePacket(clientPkt)
		if err != nil {
			log.Println("error writing to server:", err)
			return
		}
		if clientPkt.ID == 0x00 && p.state.Load() == stateHandshake {
			p.state.Store(stateStatusOrLogin)
		} else if clientPkt.ID == 0x00 && p.state.Load() == stateStatusOrLogin {
			if len(clientPkt.Data) == 0 { // status
				continue
			} else {
				log.Println("login phase")
				p.state.Store(stateLogin)
			}
		} else if clientPkt.ID == 0x03 && p.state.Load() == stateLogin {
			log.Println("config phase")
			p.state.Store(stateConfiguration)
		} else if clientPkt.ID == 0x03 && p.state.Load() == stateConfiguration {
			log.Println("play phase")
			p.state.Store(statePlay)
		}
	}

}

func (p *Pipe) handleServerFwd() {
	pkt := pk.Packet{}
	out, err := os.OpenFile(*target, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		log.Fatal(err)
	}
	for {
		err := p.serverConn.ReadPacket(&pkt)
		if err != nil {
			return
		}
		if pkt.ID == packetid.LoginCompression && p.state.Load() == stateLogin {
			var threshold pk.VarInt
			err = pkt.Scan(&threshold)
			if err != nil {
				log.Println("Error scanning for compression threshold")
				return
			}
			log.Println("set compression with threshold", threshold)
			p.serverConn.SetThreshold(int(threshold))
			// setting threshold for clientConn causes problem, idk why
			continue
		} else if pkt.ID == 0x07 && p.state.Load() == stateConfiguration {
			var name pk.Identifier
			pkt.Scan(&name)
			log.Println("Receive registry", name)
			pkt.Pack(out, *compress)
		}
		err = p.clientConn.WritePacket(pkt)
		if err != nil {
			return
		}
	}
}
