package server

import (
	"bytes"
	"encoding/binary"
	"io"

	pk "github.com/Tnze/go-mc/net/packet"
)

// RawBytes 用于直接写入字节流，避免 pk.ByteArray 添加多余的长度头
type RawBytes []byte

func (r RawBytes) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(r)
	return int64(n), err
}

// BitSet 实现
type BitSet []int64

func (b BitSet) WriteTo(w io.Writer) (int64, error) {
	n, err := pk.VarInt(len(b)).WriteTo(w) // Length
	if err != nil {
		return n, err
	}
	for _, v := range b {
		err := binary.Write(w, binary.BigEndian, v) // Longs
		if err != nil {
			return n, err
		}
		n += 8
	}
	return n, nil
}

// BuildEmptyChunkPacket 适配 Minecraft 1.21.4 / 1.21.5+
func BuildEmptyChunkPacket(chunkX, chunkZ int) pk.Packet {
	// 1.21.2+ 协议 Packet ID 通常还是 0x27，具体视版本而定
	const PacketID = 0x27
	const SectionCount = 24 // Overworld (-64 to 320)

	// --- 1. 构造 Heightmaps (1.21.5 新格式: 结构体数组) ---
	// 格式: [Count(VarInt)] -> [Type(VarInt)] + [DataLength(VarInt)] + [Longs...]
	var hmBuf bytes.Buffer

	// Count: 1 个高度图
	pk.VarInt(1).WriteTo(&hmBuf)

	// Heightmap Entry 1: MOTION_BLOCKING
	// ID: 4 (MOTION_BLOCKING, 见 Wiki)
	pk.VarInt(4).WriteTo(&hmBuf)

	// Data: Prefixed Array of Long
	// Length: 37 (384 blocks / (64 / 9 bits) = 37 longs)
	pk.VarInt(37).WriteTo(&hmBuf)

	// 写入 37 个 0 (代表高度均为 0)
	for i := 0; i < 37; i++ {
		binary.Write(&hmBuf, binary.BigEndian, int64(0))
	}

	// --- 2. 构造 Chunk Data (Sections) ---
	var dataBuf bytes.Buffer
	for i := 0; i < SectionCount; i++ {
		// Non-air block count: 0
		binary.Write(&dataBuf, binary.BigEndian, int16(0))

		// Block States: Paletted Container (Single Value)
		dataBuf.WriteByte(0)           // Bits Per Entry = 0
		pk.VarInt(0).WriteTo(&dataBuf) // Palette ID = 0 (Air)
		pk.VarInt(0).WriteTo(&dataBuf) // Data Array Length = 0

		// Biomes: Paletted Container (Single Value)
		dataBuf.WriteByte(0)           // Bits Per Entry = 0
		pk.VarInt(0).WriteTo(&dataBuf) // Palette ID = 0 (Void/Plains)
		pk.VarInt(0).WriteTo(&dataBuf) // Data Array Length = 0
	}

	// --- 3. 光照掩码 ---
	// 全 1 掩码，表示所有 Section 都是 Empty (全空)
	// int64 只有 64 位，足以覆盖 26 位 (24 sections + 2 ghost)
	// 使用 0xFFFFFFFF 简单覆盖低位
	emptyMask := int64(0xFFFFFFFF)

	return pk.Marshal(
		PacketID,
		pk.Int(chunkX),
		pk.Int(chunkZ),

		// Heightmaps: 使用 RawBytes 直接写入我们构造好的结构体流
		RawBytes(hmBuf.Bytes()),

		// Data: 使用 pk.ByteArray，因为协议要求这里有 Size(VarInt) + Content
		pk.ByteArray(dataBuf.Bytes()),

		// Block Entities: 0
		pk.VarInt(0),

		// --- Light Data ---
		BitSet{},          // Sky Light Mask (Empty)
		BitSet{},          // Block Light Mask (Empty)
		BitSet{emptyMask}, // Empty Sky Light Mask (全1)
		BitSet{emptyMask}, // Empty Block Light Mask (全1)
		pk.VarInt(0),      // Sky Light Arrays Length
		pk.VarInt(0),      // Block Light Arrays Length
	)
}
