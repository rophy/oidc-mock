package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type AuthCodeData struct {
	UserSub             string
	ClientID            string
	RedirectURI         string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
}

type AccessTokenData struct {
	UserSub   string
	ClientID  string
	Scope     string
	ExpiresAt time.Time
}

type RefreshTokenData struct {
	UserSub  string
	ClientID string
	Scope    string
	AuthTime time.Time
}

type Store struct {
	mu            sync.Mutex
	authCodes     map[string]AuthCodeData
	accessTokens  map[string]AccessTokenData
	refreshTokens map[string]RefreshTokenData
}

func NewStore() *Store {
	return &Store{
		authCodes:     make(map[string]AuthCodeData),
		accessTokens:  make(map[string]AccessTokenData),
		refreshTokens: make(map[string]RefreshTokenData),
	}
}

func (s *Store) SaveAuthCode(code string, data AuthCodeData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = data
}

func (s *Store) ConsumeAuthCode(code string) (AuthCodeData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.authCodes[code]
	if !ok || time.Now().After(data.ExpiresAt) {
		delete(s.authCodes, code)
		return AuthCodeData{}, false
	}
	delete(s.authCodes, code)
	return data, true
}

func (s *Store) GetAuthCode(code string) (AuthCodeData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.authCodes[code]
	if !ok || time.Now().After(data.ExpiresAt) {
		return AuthCodeData{}, false
	}
	return data, true
}

func (s *Store) SaveAccessToken(token string, data AccessTokenData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[token] = data
}

func (s *Store) GetAccessToken(token string) (AccessTokenData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.accessTokens[token]
	if !ok {
		return AccessTokenData{}, false
	}
	if !data.ExpiresAt.IsZero() && time.Now().After(data.ExpiresAt) {
		delete(s.accessTokens, token)
		return AccessTokenData{}, false
	}
	return data, true
}

func (s *Store) SaveRefreshToken(token string, data RefreshTokenData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token] = data
}

func (s *Store) GetRefreshToken(token string) (RefreshTokenData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.refreshTokens[token]
	return data, ok
}

func (s *Store) RevokeAccessToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accessTokens, token)
}

func (s *Store) RevokeRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
}

func (s *Store) RevokeRefreshTokenAndAccessTokens(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rtData, ok := s.refreshTokens[token]
	if ok {
		for k, v := range s.accessTokens {
			if v.ClientID == rtData.ClientID && v.UserSub == rtData.UserSub {
				delete(s.accessTokens, k)
			}
		}
		delete(s.refreshTokens, token)
	}
}

func GenerateRandomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
