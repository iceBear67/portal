package server

import (
	"encoding/json"

	"github.com/Tnze/go-mc/chat"
	"github.com/Tnze/go-mc/net"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/Tnze/go-mc/yggdrasil/user"
	"github.com/go-mc/server/server/slp"
)

func (s *PortalConn) sendStatusResponse(info *slp.ServerListPing) error {
	str, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return s.conn.WritePacket(pk.Marshal(s.protocolVersion.StatusResponse(), pk.String(str)))
}

func (s *PortalConn) sendPingResponse(pkt *pk.Packet) error {
	return s.conn.WritePacket(*pkt)
}

func (s *PortalConn) sendDisconnect(message chat.Message) error {
	disconnectMsg, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return s.conn.WritePacket(pk.Marshal(s.protocolVersion.DisconnectLogin(), pk.String(disconnectMsg)))
}

func (s *PortalConn) sendLoginSuccess(playerUUID pk.UUID, playerName pk.String, properties []user.Property, strictErrorHandling bool) error {
	if s.protocolVersion == 766 || s.protocolVersion == 767 {
		return s.conn.WritePacket(pk.Marshal(
			s.protocolVersion.LoginSuccess(),
			playerUUID,
			playerName,
			pk.Array(properties),
			pk.Boolean(strictErrorHandling),
		))
	}
	return s.conn.WritePacket(pk.Marshal(
		s.protocolVersion.LoginSuccess(),
		playerUUID,
		playerName,
		pk.Array(properties),
	))
}

func (s *PortalConn) sendFinishConfiguration() error {
	return s.conn.WritePacket(pk.Marshal(s.protocolVersion.FinishConfiguration()))
}

func (s *PortalConn) sendTransfer(host string, port int) error {
	packetId := s.protocolVersion.TransferPlay()
	if s.state == stateConfig {
		packetId = s.protocolVersion.TransferConfig()
	}
	return s.conn.WritePacket(pk.Marshal(packetId, pk.String(host), pk.VarInt(port)))
}

func (s *PortalConn) sendBrand(brand string) error {
	return s.conn.WritePacket(pk.Marshal(s.protocolVersion.PluginChannelConfig(), pk.String("minecraft:brand"), pk.String(brand)))
}

func (s *PortalConn) sendKeepAliveChallenge(challenge int64) error {
	id := s.protocolVersion.ClientboundKeepalivePlay()
	if s.state == stateConfig {
		id = s.protocolVersion.ClientboundKeepaliveConfig()
	}
	return s.conn.WritePacket(pk.Marshal(id, pk.Long(challenge)))
}

func (s *PortalConn) sendLoginPlay() error {
	return s.conn.WritePacket(pk.Marshal(s.protocolVersion.LoginPlay(),
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
}

func (s *PortalConn) sendEmptyChunk(chunkX int, chunkZ int) error {
	return s.conn.WritePacket(BuildEmptyChunkPacket(chunkX, chunkZ)) //todo cache
}

func (s *PortalConn) sendGameEvent13() error {
	return s.conn.WritePacket(pk.Marshal(0x22, pk.UnsignedByte(13), pk.Float(0))) // gameevent 13
}

func (s *PortalConn) sendSynchronizePosition() error {
	return s.conn.WritePacket(pk.Marshal(0x41, pk.VarInt(1919), // Synchronize position todo cache
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
