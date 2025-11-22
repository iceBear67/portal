package server

import (
	"sort"
)

type RegistryData struct {
	protocolVersion ProtocolVersion
	value           func() []byte
}

func (d *RegistryData) ProtocolVersion() ProtocolVersion {
	return d.protocolVersion
}
func (d *RegistryData) Value() []byte {
	return d.value()
}

type RegistryMap struct {
	data *[]RegistryData
}

func (m *RegistryMap) Put(version int, data []byte) {
	*m.data = append(*m.data, RegistryData{
		protocolVersion: ProtocolVersion(version),
		value:           func() []byte { return data },
	})
	sort.Slice(*m.data, func(i, j int) bool {
		return (*m.data)[i].protocolVersion < (*m.data)[j].protocolVersion
	})
}

func (m *RegistryMap) Next(version ProtocolVersion) (*RegistryData, bool) {
	data := *m.data
	i := sort.Search(len(data), func(i int) bool {
		return data[i].protocolVersion > version
	})
	if i < len(data) {
		return &data[i], true
	}
	return nil, false
}
