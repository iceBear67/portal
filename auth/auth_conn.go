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

	// for players from different source to bind their identity
	needSecondAuth bool
	authListener   AuthenticatedListener
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
	return err
}

func (s *AuthConnHandler) OnServerNameIndicated(conn *limbo.PortalConn, serverName string) error {
	return nil
}

func (s *AuthConnHandler) OnTransfer(conn *limbo.PortalConn, target string) {

}

func (s *AuthConnHandler) OnAuthentication(conn *limbo.PortalConn, sendLimbo func() error, transfer func() error) error {
	online := conn.IsUserOnline()

	source := s.authSource
	tx, err := s.server.database.Beginx()
	if err != nil {
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	db := Access(tx)
	_result, err := db.FindById(*conn.PlayerId()) //todo add a timeout here
	_ = tx.Rollback()
	if err != nil {
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	accountRecords := *_result

	if len(accountRecords) == 0 {
		if !s.server.config.OpenRegistration {
			return s.authListener.OnAuthenticateResult(conn, errors.New("registration closed"))
		}
		s.needRegistration = true
		return sendLimbo()
	}
	if online && s.server.config.YggdrasilBypass {
		if !s.server.config.StrictSourceValidation {
			return transfer()
		}

		for _, r := range accountRecords {
			if r.Source == source {
				return transfer()
			}
		}
		return errors.Join(s.authListener.OnAuthenticateResult(conn, errors.New("account not found")))
	}
	return sendLimbo()
}

func (s *AuthConnHandler) OnLimboJoin(conn *limbo.PortalConn) error {
	return nil
}

func (s *AuthConnHandler) OnPlayerReady(conn *limbo.PortalConn) error {
	if s.needRegistration {
		return s.initiateRegistrationFlow(conn)
	}
	tx, err := s.server.database.Beginx()
	if err != nil {
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	access := Access(tx)
	pwdR, err := access.GetPasswordById(*conn.PlayerId())
	if err != nil { //todo more detailed err: user not exist
		return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
	}
	_ = tx.Rollback()
	return s.initiateLoginFlow(conn, pwdR)
}

func (s *AuthConnHandler) initiateLoginFlow(conn *limbo.PortalConn, pwdR *PasswordRecord) error {
	var pkt pk.Packet
	msg := chat.Text("Login")
	subT := chat.Text("Please enter your password")
	err := conn.SendTitle(&msg, &subT)

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
			if !ValidatePassword(strings.Trim(msg, " "), pwdR.Password) {
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
	_ uuid.UUID,
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
	msg := chat.Text("+ Register +")
	subT := chat.Text("Press T to type password")
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
				if err := conn.SendChatMessage(chat.Text("Password mismatch. try your password again."), false); err != nil {
					return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
				}
				continue
			}
			if err := conn.SendChatMessage(chat.Text("Registering your account, please wait."), false); err != nil {
				return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
			}
			finalPassword := msg2
			// register
			regCtx, cancelFn := context.WithCancel(conn.Context())

			s.server.registerQueue <- &DatabaseOp{
				action: func(acc *DatabaseAccess) error {
					ur := UserRecord{
						Name:         conn.PlayerName(),
						Id:           *conn.PlayerId(),
						RegisterTime: time.Now(),
						Source:       s.authSource,
					}
					err := acc.TryRegister(ur)
					if err != nil {
						return err
					}
					err = acc.SetPassword(*conn.PlayerId(), finalPassword)
					if err != nil {
						return err
					}
					return nil
				},
				callback: func(err error) {
					defer cancelFn()
					if err != nil {
						_ = conn.SendDisconnect(chat.Text("Failed to register your account. Please try again later."))
						log.Println("Failed to register account for", conn.PlayerName(), ":", err)
						return
					}
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
