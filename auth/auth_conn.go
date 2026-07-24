package auth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Tnze/go-mc/chat"
	pk "github.com/Tnze/go-mc/net/packet"
	"github.com/go-mc/server/limbo"
	"github.com/google/uuid"
	"github.com/icebear67/mfp-go"
	"github.com/icebear67/mfp-go/pip"
)

// errNameTaken is returned during registration when the requested name is
// already registered under a different uuid and collisions are disallowed.
var errNameTaken = errors.New("name already registered by another account")

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

func (s *AuthConnHandler) OnAuthenticateResult(conn *limbo.PortalConn, err error) error {
	_ = conn.SendDisconnect(chat.Text(err.Error()))
	return err
}

func (s *AuthConnHandler) OnServerNameIndicated(conn *limbo.PortalConn, serverName string) error {
	return nil
}

func (s *AuthConnHandler) OnTransfer(conn *limbo.PortalConn, target string, port int) error {
	// set info
	dest := conn.Destination()
	if dest == nil {
		return fmt.Errorf("unknown destination")
	}
	id := s.server.Identity()
	rt, err := pip.Issue(id, pip.TokenParams{
		Target:  mfp.PublicKey(dest.PublicKey),
		Subject: conn.PlayerId()[:],
		Profile: &pip.PlayerProfile{
			Name:       conn.PlayerName(),
			Texture:    nil,
			Cape:       nil,
			Extensions: nil,
		},
		Time:  time.Now(),
		Until: time.Now().Add(time.Minute * 1),
	})
	if err != nil {
		conn.Logf("error issuing redirect token: %v", err)
		return fmt.Errorf("cannot issue transfer packet")
	}
	bytes, err := rt.Marshal()
	if err != nil {
		conn.Logf("error marshaling redirect token: %v", err)
		return fmt.Errorf("cannot marshal transfer packet")
	}
	cookies, err := pip.Chunk("pip:redirect", bytes)
	if err != nil {
		conn.Logf("error chunking redirect token: %v", err)
		return fmt.Errorf("cannot issue redirect packet")
	}
	for k, v := range cookies {
		if err = conn.SetCookie(k, v); err != nil {
			conn.Logf("error setting cookie %v: %v", k, err)
			return fmt.Errorf("cannot set cookie %v", k)
		}
	}
	return nil
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
			if err := conn.SendChatMessage(chat.Text("Confirm your password by sending it again"), false); err != nil {
				return errors.Join(err, s.authListener.OnAuthenticateResult(conn, err))
			}
			// Only a chat packet carries the confirmation; skip anything else
			// (e.g. a keepalive response) that may arrive in between.
			var msg2 string
			for {
				if err := conn.Connection().ReadPacket(&pkt); err != nil {
					return err
				}
				if int(pkt.ID) != conn.ProtocolVersion().ChatMessage() {
					continue
				}
				var e error
				msg2, e = conn.ReadChatMessage(&pkt)
				if e != nil {
					return e
				}
				break
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

			op := &DatabaseOp{
				action: func(acc *DatabaseAccess) error {
					// Reject registering a name already owned by a different
					// uuid, unless name collisions are explicitly allowed. Done
					// inside the write tx so the check and insert are atomic.
					if !s.server.config.AllowNameCollision {
						existing, err := acc.FindByNameUnorder(conn.PlayerName())
						if err != nil {
							return err
						}
						for _, r := range *existing {
							if r.Id != *conn.PlayerId() {
								return errNameTaken
							}
						}
					}
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
						msg := "Failed to register your account. Please try again later."
						if errors.Is(err, errNameTaken) {
							msg = "This name is already registered by another account."
						}
						_ = conn.SendDisconnect(chat.Text(msg))
						conn.Logf("registration failed: %v", err)
						return
					}
					_ = conn.SendChatMessage(chat.Text("Registration successfully. You'll be redirected soon"), false)
					if err = conn.TransferDestination(); err != nil {
						conn.Logf("failed to redirect after registration: %v", err)
						return
					}
				},
			}
			// ctx-aware send so we don't block forever if the writer has
			// already stopped (ctx cancelled).
			select {
			case s.server.registerQueue <- op:
			case <-conn.Context().Done():
				cancelFn()
				return conn.Context().Err()
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
