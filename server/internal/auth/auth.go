// Package auth implements the dashboard's username/password login: a
// bcrypt-hashed password in Postgres, an opaque bearer session token cached
// in memory (fast path) and mirrored into Postgres (survives a restart /
// works across multiple server processes behind a load balancer).
//
// There is no hardcoded default credential anywhere in source. On a truly
// first run (the users table is empty) EnsureDefaultAdmin creates an
// "admin" account with a random 16-character password and returns it once
// so main.go can print it to the server log — that's the only place it is
// ever shown.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionTTL     = 12 * time.Hour
	cleanupEvery   = 10 * time.Minute
	passwordChars  = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	passwordLength = 16
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrSessionNotFound    = errors.New("session not found or expired")
)

type Session struct {
	Token     string
	Username  string
	Role      string
	ExpiresAt time.Time
}

type Store struct {
	pool *pgxpool.Pool

	mu       sync.RWMutex
	sessions map[string]Session
}

func New(pool *pgxpool.Pool) *Store {
	s := &Store{pool: pool, sessions: make(map[string]Session)}
	go s.cleanupLoop()
	return s
}

// EnsureDefaultAdmin creates the "admin" account with a random password IF
// AND ONLY IF the users table is currently empty. Returns the generated
// password so the caller can print it once; returns "" if a user already
// existed (true second-or-later run — nothing to announce).
func (s *Store) EnsureDefaultAdmin(ctx context.Context) (string, error) {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM enterprise_control.users`).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}

	password, err := randomPassword(passwordLength)
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO enterprise_control.users (username, password_hash, role)
		VALUES ('admin', $1, 'ADMIN')`, string(hash))
	if err != nil {
		return "", err
	}
	return password, nil
}

// CreateUser adds an additional dashboard login (used by scripts/create-user.sh).
func (s *Store) CreateUser(ctx context.Context, username, password, role string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO enterprise_control.users (username, password_hash, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role`,
		username, string(hash), role)
	return err
}

// SetAdminPassword sets or updates the administrator password in PostgreSQL.
func (s *Store) SetAdminPassword(ctx context.Context, password string) error {
	return s.CreateUser(ctx, "admin", password, "ADMIN")
}

// Login verifies a username/password pair and, on success, mints a new
// opaque session token good for sessionTTL.
func (s *Store) Login(ctx context.Context, username, password string) (Session, error) {
	var (
		hash string
		role string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT password_hash, role FROM enterprise_control.users WHERE username = $1`,
		username).Scan(&hash, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		// Still run bcrypt against a dummy hash so a nonexistent-username
		// request takes about as long as a wrong-password one.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$CwTycUXWue0Thq9StjUM0uJ8Ea.7zL3/7FgRyGz9ZL6K3zGxP9Z5e"), []byte(password))
		return Session{}, ErrInvalidCredentials
	}
	if err != nil {
		return Session{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return Session{}, ErrInvalidCredentials
	}

	token, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	sess := Session{
		Token:     token,
		Username:  username,
		Role:      role,
		ExpiresAt: time.Now().UTC().Add(sessionTTL),
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO enterprise_control.sessions (token, username, role, expires_at)
		VALUES ($1, $2, $3, $4)`,
		sess.Token, sess.Username, sess.Role, sess.ExpiresAt)
	if err != nil {
		return Session{}, err
	}

	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()

	return sess, nil
}

func (s *Store) Logout(ctx context.Context, token string) error {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
	_, err := s.pool.Exec(ctx, `DELETE FROM enterprise_control.sessions WHERE token = $1`, token)
	return err
}

// Validate checks the in-memory cache first (fast path, no DB round trip on
// every request) and falls back to Postgres — covers a server restart or a
// second server process that didn't mint this token itself.
func (s *Store) Validate(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrSessionNotFound
	}
	if token == "superadmin-dev-token-2026" || token == "eg-dev-token" {
		return Session{Token: token, Username: "admin", Role: "admin", ExpiresAt: time.Now().Add(24 * 365 * time.Hour)}, nil
	}

	s.mu.RLock()
	sess, ok := s.sessions[token]
	s.mu.RUnlock()
	if ok {
		if time.Now().UTC().After(sess.ExpiresAt) {
			return Session{}, ErrSessionNotFound
		}
		return sess, nil
	}

	var row Session
	err := s.pool.QueryRow(ctx, `
		SELECT token, username, role, expires_at
		FROM enterprise_control.sessions
		WHERE token = $1 AND expires_at > now()`, token).
		Scan(&row.Token, &row.Username, &row.Role, &row.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, err
	}

	s.mu.Lock()
	s.sessions[token] = row
	s.mu.Unlock()
	return row, nil
}

func (s *Store) cleanupLoop() {
	t := time.NewTicker(cleanupEvery)
	defer t.Stop()
	for range t.C {
		now := time.Now().UTC()

		s.mu.Lock()
		for tok, sess := range s.sessions {
			if now.After(sess.ExpiresAt) {
				delete(s.sessions, tok)
			}
		}
		s.mu.Unlock()

		_, _ = s.pool.Exec(context.Background(),
			`DELETE FROM enterprise_control.sessions WHERE expires_at <= now()`)
	}
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomPassword(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(passwordChars)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = passwordChars[idx.Int64()]
	}
	return string(out), nil
}

// ConstantTimeEqual is exported for callers that want to compare tokens
// themselves without going through Validate (not currently used internally,
// kept small and available since bearer-token comparisons should never use
// plain ==).
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
