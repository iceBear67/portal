package main

import (
	"encoding/json"

	"github.com/Tnze/go-mc/chat"
	"github.com/Tnze/go-mc/data/packetid"
	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/Tnze/go-mc/yggdrasil/user"
)

func (s *PortalConn) sendStatusResponse(info *ServerListPing) error {
	str, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return s.conn.WritePacket(pk.Marshal(0x00, pk.String(str)))
}

func (s *PortalConn) sendPingResponse(pkt *pk.Packet) error {
	return s.conn.WritePacket(*pkt)
}

func (s *PortalConn) sendDisconnect(message chat.Message) error {
	disconnectMsg, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return s.conn.WritePacket(pk.Marshal(0x00, pk.String(disconnectMsg)))
}

func (s *PortalConn) sendLoginSuccess(playerUUID pk.UUID, playerName pk.String, properties []user.Property, strictErrorHandling bool) error {
	if s.protocolVersion == 766 || s.protocolVersion == 767 {
		return s.conn.WritePacket(pk.Marshal(
			int(packetid.LoginSuccess),
			playerUUID,
			playerName,
			pk.Array(properties),
			pk.Boolean(strictErrorHandling),
		))
	}
	return s.conn.WritePacket(pk.Marshal(
		int(packetid.LoginSuccess),
		playerUUID,
		playerName,
		pk.Array(properties),
	))
}

func (s *PortalConn) sendFinishConfiguration() error {
	return s.conn.WritePacket(pk.Marshal(0x03))
}

func (s *PortalConn) sendTransfer(host string, port int) error {
	packetId := 0
	if s.state == stateConfiguration {
		packetId = 0x0B
	} else {
		packetId = 0x7A
	}
	return s.conn.WritePacket(pk.Marshal(packetId, pk.String(host), pk.VarInt(port)))
}

func sendHandshakePacket(conn *net.Conn, protocolVersion int, serverAddress string, serverPort int, nextState int) error {
	return conn.WritePacket(pk.Marshal(
		0x00,
		pk.VarInt(protocolVersion),
		pk.String(serverAddress),
		pk.UnsignedShort(serverPort),
		pk.VarInt(nextState),
	))
}

func sendStatusRequest(conn *net.Conn) error {
	return conn.WritePacket(pk.Marshal(0x00))
}
