package slp

import (
	"github.com/Tnze/go-mc/chat"
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
