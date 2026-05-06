package auth

import (
	"github.com/go-mc/server/limbo"
	"github.com/google/uuid"
)

type BindConnHandler struct {
	bindTarget uuid.UUID
	authConn   *AuthConnHandler
}

func (b BindConnHandler) OnAuthenticateResult(conn *limbo.PortalConn, err error) error {
	//TODO implement me
	panic("implement me")
}
