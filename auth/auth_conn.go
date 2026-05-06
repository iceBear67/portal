package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Tnze/go-mc/chat"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/go-mc/server/limbo"
	"github.com/google/uuid"
)

type AuthConnHandler struct {
	server           *AuthServer
	authSource       string
	needRegistration bool
	authListener     AuthenticatedListener
}

type AuthenticatedListener interface {
	// OnAuthenticateResult when err is present, no guarantee of existence or integrity of player information.
	// AuthConnHandler continue executing the default behavior if no error is returned.
	OnAuthenticateResult(conn *limbo.PortalConn, err error) error
}

func (s *AuthConnHandler) Init(conn *limbo.PortalConn) error {
	s.authListener = s
	return nil
}

// todo refactor other kick logics to here.
func (s *AuthConnHandler) OnAuthenticateResult(conn *limbo.PortalConn, err error) error {
	return nil
}

func (s *AuthConnHandler) OnServerNameIndicated(conn *limbo.PortalConn, serverName string) error {
	v, ok := s.server.bindingPlayers[serverName] // todo did you trim the name?
	if ok {
		s.authListener = &BindConnHandler{authConn: s, bindTarget: v}
	}
	return nil
}

func (s *AuthConnHandler) OnTransfer(conn *limbo.PortalConn, target string) {

}

func (s *AuthConnHandler) OnAuthentication(conn *limbo.PortalConn, sendLimbo func() error, transfer func() error) error {
	online := conn.Online()
	if (online && s.server.config.YggdrasilBypass) ||
		(!online && s.server.config.OfflineBypass) {
		if err := s.authListener.OnAuthenticateResult(conn, nil); err != nil {
			return err
		}
		return transfer()
	}
	source := s.authSource
	db, err := Access(s.server.database)
	if err != nil {
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	_result, err := db.FindById(*conn.PlayerId())
	if err != nil {
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	result := *_result

	// rule 1: if open registration and not registered yet, register.
	if len(result) == 0 && s.server.config.OpenRegistration {
		// handle new user
		if online {
			return s.handleOnlineEarlyRegister(conn, sendLimbo, transfer)
		} else {
			// todo set additional context
			return sendLimbo()
		}
	}
	// rule 2: same uuid but source, reject until registration.
	if online {
		for _, r := range result {
			if r.Source == source {
				return transfer()
			}
		}
	} else {
		return sendLimbo()
	}
	//todo i18n
	return errors.Join(s.authListener.OnAuthenticateResult(conn, errors.New("uuid conflict")), conn.SendDisconnect(chat.Text(`
- Access Denied -

Another player %v has registered from %v with the same UUID.
If you're this player, please login the authentication server %v with account from %v
So we can confirm they are you.
`)))
}

// Automatically register new accounts for online players.
func (s *AuthConnHandler) handleOnlineEarlyRegister(conn *limbo.PortalConn, sendLimbo func() error, transfer func() error) error {
	ctx, cancel := context.WithCancel(s.server.server.Ctx())
	var finalErr error
	s.server.registerQueue <- &RegisterRequest{
		record: UserRecord{
			Name:         conn.PlayerName(), // todo trim the name and validate.
			Id:           *conn.PlayerId(),
			RegisterTime: time.Now(),
			Source:       s.authSource, // trusted because this is a real online player.
		},
		callback: func(err error) {
			defer cancel()
			if err != nil {
				finalErr = fmt.Errorf(
					"failed to register account for yggdrasil player %v (from %v): %v",
					conn.PlayerName(), s.authSource, err)
				//user duplication or database error.
				_ = conn.SendDisconnect(chat.Text("An unexpected error has occurred. Contact administrator for help"))
				return
			}
			log.Println("automatically registered account for yggdrasil player", conn.PlayerName(), "from", s.authSource)
			finalErr = transfer()
		},
	}
	select {
	case <-ctx.Done():
		cancel()
		if finalErr != nil {
			return finalErr
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		return nil
	}
}

func (s *AuthConnHandler) OnLimboJoin(conn *limbo.PortalConn) error {
	return nil
}

func (s *AuthConnHandler) OnPlayerReady(conn *limbo.PortalConn) error {
	// situation 0. register
	if !s.server.config.OpenRegistration {
		err := fmt.Errorf("the server hasn't open registration")
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	if s.needRegistration {
		return s.initiateRegistrationFlow(conn)
	}
	// situation > 0: offline login.
	// situation 1. normal offline login flow, conn.UUID is the right offline ID
	// situation 2. yggdrasil fallback, the conn.UUID was suggested by the client.
	// anyway the uuid is right :)
	access, err := Access(s.server.database)
	if err != nil {
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	pwdR, err := access.GetPasswordById(*conn.PlayerId())
	if err != nil { //todo more detailed err: user not exist
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	var pkt pk.Packet
	msg := chat.Text("Login")
	subT := chat.Text("Please enter your password")
	err = conn.SendTitle(&msg, &subT)

	passwordWrongCounter := 0
	if err != nil {
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	for {
		err := conn.Connection().ReadPacket(&pkt)
		if err != nil {
			return err
		}
		if int(pkt.ID) == conn.ProtocolVersion().ChatMessage() {
			msg, e := conn.ReadChatMessage(&pkt)
			if e != nil {
				return errors.Join(e, s.authListener.OnAuthenticateResult(conn, e))
			}
			if !ValidatePassword(strings.Trim(msg, " "), []byte(pwdR.Password)) {
				chat.Text("Incorrect password, please try again later.")
				passwordWrongCounter += 1
				// todo integrate with security features, like rate limiter.
				if passwordWrongCounter >= 3 {
					_ = s.authListener.OnAuthenticateResult(conn, errors.New("invalid password"))
					return conn.SendDisconnect(chat.Text("Too many wrong tries."))
				}
				continue
			}
			// pass
			return conn.TransferDestination()
		}
	}
}

func (s *AuthConnHandler) OnPlayerChat(conn *limbo.PortalConn, message string) {
}

func (s *AuthConnHandler) OnStateTransition(conn *limbo.PortalConn, newState int) {
	if newState == limbo.StateLogin {
		s.authSource = "offline" // init
	}
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
	_ = s.authListener.OnAuthenticateResult(conn, errors.New("no available yggdrasil server"))
	return nil, fmt.Errorf("no auth servers available")
}

func (s *AuthConnHandler) OnDisconnect(conn *limbo.PortalConn) {

}

func (s *AuthConnHandler) initiateRegistrationFlow(conn *limbo.PortalConn) error {
	var pkt pk.Packet
	msg := chat.Text("Register")
	subT := chat.Text("Please enter your password")
	_ = conn.SendTitle(&msg, &subT)
	for {
		if err := conn.Connection().ReadPacket(&pkt); err != nil {
			return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
		}
		if int(pkt.ID) == conn.ProtocolVersion().ChatMessage() {
			msg, e := conn.ReadChatMessage(&pkt)
			if e != nil {
				return errors.Join(e, s.authListener.OnAuthenticateResult(conn, e))
			}
			// todo trim
			if err := conn.SendChatMessage(chat.Text("Confirm your password by sending it again"), false); err != nil {
				return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
			}
			if err := conn.Connection().ReadPacket(&pkt); err != nil {
				return err
			}
			msg2, e := conn.ReadChatMessage(&pkt)
			if e != nil {
				return e
			}
			if msg != msg2 {
				if err := conn.SendChatMessage(chat.Text("Password mismatch. You may try your password again."), false); err != nil {
					return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
				}
				continue
			}
			if err := conn.SendChatMessage(chat.Text("Registering your account, please wait."), false); err != nil {
				return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
			}
			// register
			regCtx, cancelFn := context.WithCancel(conn.Context())
			s.server.registerQueue <- &RegisterRequest{
				record: UserRecord{
					Name:         conn.PlayerName(),
					Id:           *conn.PlayerId(),
					RegisterTime: time.Now(),
					Source:       s.authSource,
				},
				callback: func(err error) {
					defer cancelFn()
					if err != nil {
						log.Println("Failed to register account for", conn.PlayerName(), ":", err)
						return
					}
					// ignore error
					_ = conn.SendChatMessage(chat.Text("Registration successfully. You'll be redirected soon"), false)
					if err = conn.TransferDestination(); err != nil {
						log.Println("Failed to redirect", conn.PlayerName(), "after registration. err:", err)
						return
					}
				},
			}
			select {
			case <-regCtx.Done():
				if !errors.Is(regCtx.Err(), context.Canceled) {
					return regCtx.Err()
				}
			}
			return nil
		}
	}

}
