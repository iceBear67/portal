package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/go-mc/server/server/slp"
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

func (s *PortalConn) goTransfer(serverAddr string) error {
	// set cookies...todo
	log.Println("Redirecting", s.playerId, "to", serverAddr)
	s.listener.onTransfer(s, serverAddr)
	split := strings.Split(serverAddr, ":")
	if len(split) != 2 {
		return fmt.Errorf("invalid server address, expect host:port %v", serverAddr)
	}
	port, err := strconv.Atoi(split[1])
	if err != nil {
		return err
	}
	if err := s.SendTransfer(split[0], port); err != nil {
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

func HarvestStatus(serverAddr string, ctx context.Context, timeout time.Duration) (*slp.ServerListPing, error) {
	conn, err := net.DialMCTimeout(serverAddr, timeout)
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
	arr := strings.Split(serverAddr, ":")
	port, err := strconv.Atoi(arr[1])
	if err != nil {
		port = 25565
	}
	err = sendHandshakePacket(conn, 0, arr[0], port, 1)
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
