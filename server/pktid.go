package server

func (s ProtocolVersion) StatusResponse() int {
	return 0x00
}

func (s ProtocolVersion) DisconnectLogin() int {
	return 0x00
}

func (s ProtocolVersion) LoginSuccess() int {
	return 0x02
}

func (s ProtocolVersion) FinishConfiguration() int {
	return 0x03
}

func (s ProtocolVersion) TransferConfig() int {
	return 0x0B
}

func (s ProtocolVersion) TransferPlay() int {
	return 0x7A
}

func (s ProtocolVersion) PluginChannelConfig() int {
	return 0x01
}

func (s ProtocolVersion) ClientboundKeepaliveConfig() int {
	return 0x04
}

func (s ProtocolVersion) ClientboundKeepalivePlay() int {
	return 0x26
}

func (s ProtocolVersion) LoginAcknowledged() int {
	return 0x03
}

func (s ProtocolVersion) LoginPlay() int {
	return 0x2b
}

func (s ProtocolVersion) SynchronizePosition() int {
	return 0x41
}

func (s ProtocolVersion) GameEvent() int {
	return 0x22
}

func (s ProtocolVersion) ResetChatPlay() int {
	return 0x06
}
