package limbo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/go-mc/server/limbo/slp"
)

func (s *PortalConn) runKeepAlive(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = s.sendKeepAliveChallenge(time.Now().UnixNano() / 1e6)
			if s.ctx.Err() != nil {
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *PortalConn) TransferDestination() error {
	if s.destination == nil {
		return errors.New("no destination")
	}
	return s.goTransfer(s.destination.DestinationHost, s.destination.DestinationPort)
}

func (s *PortalConn) goTransfer(serverHost string, serverPort int) error {
	// set cookies... should be done by downstream connection implementations.
	if s.state != StateConfig && s.state != StatePlay {
		return errors.New("invalid state invoking transfer")
	}
	log.Println("Redirecting", s.playerId, "to", serverHost)
	s.listener.OnTransfer(s, serverHost, serverPort)
	if err := s.SendTransfer(serverHost, serverPort); err != nil {
		return err
	}
	// waiting for transfer
	select {
	case <-time.After(time.Second * 5):
		return nil
	case <-s.ctx.Done():
		return nil
	}
}

func HarvestStatus(serverAddr *ServerConfig, ctx context.Context, timeout time.Duration) (*slp.ServerListPing, error) {
	conn, err := net.DialMCTimeout(fmt.Sprintf("%v:%v", serverAddr.DestinationHost, serverAddr.DestinationPort), timeout)
	if err != nil {
		return nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		}
	}()
	defer func() {
		conn.Close()
	}()
	err = sendHandshakePacket(conn, 0, serverAddr.DestinationHost, serverAddr.DestinationPort, 1)
	if err != nil {
		return nil, err
	}
	err = sendStatusRequest(conn)
	if err != nil {
		return nil, err
	}
	pkt := pk.Packet{}
	err = conn.ReadPacket(&pkt)
	if err != nil {
		return nil, err
	}
	if pkt.ID != 00 {
		return nil, fmt.Errorf("invalid packet id while fetching status: %v", pkt.ID)
	}
	var str pk.String
	err = pkt.Scan(&str)
	if err != nil {
		return nil, err
	}
	var r = slp.ServerListPing{}
	err = json.Unmarshal([]byte(str), &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func Map[T, V any](ts []T, fn func(T) V) []V {
	result := make([]V, len(ts))
	for i, t := range ts {
		result[i] = fn(t)
	}
	return result
}
