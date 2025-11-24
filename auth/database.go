package auth

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

const SQLiteSchema = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS user_record (
    "index"         INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    uuid            TEXT NOT NULL,
    time            TEXT NOT NULL,        -- RFC3339 time string
    source          TEXT
);

CREATE TABLE IF NOT EXISTS password_record (
    "index"     INTEGER PRIMARY KEY,
    uuid        TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    FOREIGN KEY (uuid) REFERENCES user_record(uuid)
);
`

type UserRecord struct {
	Index        int64     `db:"index"`
	Name         string    `db:"name"`
	Id           uuid.UUID `db:"uuid"`
	RegisterTime time.Time `db:"time"`
	Source       string    `db:"source"`
}

type PasswordRecord struct {
	Index    int64     `db:"index"`
	Id       uuid.UUID `db:"uuid"`
	Password string    `db:"password"`
}

type DatabaseAccess struct {
	db *sqlx.Tx
}

func Access(db *sqlx.DB) (*DatabaseAccess, error) {
	tx, err := db.Beginx()
	if err != nil {
		return nil, err
	}
	return &DatabaseAccess{db: tx}, nil
}

func (s *DatabaseAccess) Commit() error {
	return s.db.Commit()
}

func (s *DatabaseAccess) FindById(id uuid.UUID) (*[]UserRecord, error) {
	records := []UserRecord{}
	err := s.db.Select(&records, "SELECT * FROM user_record WHERE uuid = ? ORDER BY time ASC", id)
	if err != nil {
		return nil, err
	}
	return &records, nil
}

func (s *DatabaseAccess) FindByNameUnorder(name string) (*[]UserRecord, error) {
	records := []UserRecord{}
	err := s.db.Select(&records, "SELECT * FROM user_record WHERE name = ?", name)
	if err != nil {
		return nil, err
	}
	return &records, nil
}

func (s *DatabaseAccess) GetPasswordById(id uuid.UUID) (*PasswordRecord, error) {
	record := PasswordRecord{}
	err := s.db.Get(&record, "SELECT * FROM password_record WHERE uuid = ?", id)
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *DatabaseAccess) TryRegister(record UserRecord) error {
	var count int
	err := s.db.Get(&count, "SELECT COUNT(*) FROM user_record WHERE uuid = ?", record.Id)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("user already registered")
	}
	_, err = s.db.Exec("INSERT INTO user_record (name,uuid,time,source) VALUES (?, ?, ?, ?)",
		record.Name, record.Id, record.RegisterTime, record.Source)
	if err != nil {
		return err
	}
	return nil
}

type RegisterRequest struct {
	record   UserRecord
	callback func(err error)
}

func createWriter(db *sqlx.DB, ctx context.Context) (chan *RegisterRequest, error) {
	ch := make(chan *RegisterRequest, 16)
	go func() {
		select {
		case <-ctx.Done():
			close(ch)
		}
	}()
	go func() {
		for req := range ch {
			acc, err := Access(db)
			if err != nil {
				log.Println("Failed to access database.")
			}
			err = acc.TryRegister(req.record)
			req.callback(err)
		}
	}()
	return ch, nil
}
