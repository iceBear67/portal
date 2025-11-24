package auth

import (
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/Tnze/go-mc/yggdrasil/user"
	"github.com/go-mc/server/limbo"
	"github.com/google/uuid"
)

type AuthConnHandler struct {
	server     *AuthServer
	authSource string
	fallback   bool
}

func (s *AuthConnHandler) OnTransfer(conn *limbo.PortalConn, target string) {

}

func (s *AuthConnHandler) OnAuthentication(conn *limbo.PortalConn, online bool) (setupLimbo bool) {
	if (online && s.server.config.YggdrasilBypass) ||
		(!online && s.server.config.OfflineBypass) {
		return false
	}
	// 验证来源和 uuid 冲突
	// todo
	if s.fallback {
		return true
	}
	return true
}

func (s *AuthConnHandler) OnLimboJoin(conn *limbo.PortalConn) {
}

func (s *AuthConnHandler) OnPlayerReady(conn *limbo.PortalConn) {
}

func (s *AuthConnHandler) OnPlayerChat(conn *limbo.PortalConn, message string) {
}

func (s *AuthConnHandler) OnStateTransition(conn *limbo.PortalConn, newState int) {

}

func (s *AuthConnHandler) OnYggdrasilChallenge(
	conn *limbo.PortalConn,
	playerName string,
	clientSuggestedId uuid.UUID,
	privateKey *rsa.PrivateKey,
) (*limbo.Resp, error) {
	for source, item := range s.server.config.YggdrasilServers {
		resp, err := limbo.Encrypt(conn.Connection(), playerName, privateKey, true, item)
		if err != nil {
			continue
		}
		s.authSource = source
		return resp, nil
	}
	if s.server.config.YggdrasilFallback {
		s.fallback = true
		//todo dangerous operation, check the login flow
		log.Println("User", playerName, "failed to pass yggdrasil, falling back to user/pass authentication.")
		prop := []user.Property{{Name: "textures", Value: conn.Server().Config.DefaultSkin}}
		return &limbo.Resp{
			Name:       playerName,
			ID:         clientSuggestedId,
			Properties: prop,
		}, nil
	}
	return nil, fmt.Errorf("no auth servers available")
}

func (s *AuthConnHandler) OnDisconnect(conn *limbo.PortalConn) {

}
