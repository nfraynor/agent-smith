package localoauth

import (
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

func (s *Store) CreateSession(userID string, ttl time.Duration) (SessionCredentials, error) {
	if ttl <= 0 {
		return SessionCredentials{}, errors.New("session lifetime must be positive")
	}
	token, err := randomToken()
	if err != nil {
		return SessionCredentials{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return SessionCredentials{}, err
	}
	id, err := randomToken()
	if err != nil {
		return SessionCredentials{}, err
	}
	var session Session
	err = s.db.Update(func(tx *bolt.Tx) error {
		var user storedUser
		if err := getJSON(tx.Bucket(bucketUsers), userID, &user); err != nil {
			return err
		}
		if !user.Enabled {
			return ErrDisabled
		}
		now := s.now().UTC()
		session = Session{ID: "ses_" + id, UserID: userID, ExpiresAt: now.Add(ttl), LastSeenAt: now, SecurityVersion: user.SecurityVersion}
		return putJSON(tx.Bucket(bucketSessions), credentialKey(token), storedSession{Session: session, CSRFHash: credentialKey(csrf)})
	})
	if err != nil {
		return SessionCredentials{}, err
	}
	return SessionCredentials{Token: token, CSRFToken: csrf, Session: session}, nil
}

func (s *Store) GetSession(raw string) (Session, User, error) {
	var session storedSession
	var user storedUser
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := getJSON(tx.Bucket(bucketSessions), credentialKey(raw), &session); err != nil {
			return err
		}
		if !session.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		if err := getJSON(tx.Bucket(bucketUsers), session.UserID, &user); err != nil {
			return err
		}
		if !user.Enabled {
			return ErrDisabled
		}
		if session.SecurityVersion != user.SecurityVersion {
			return ErrRevoked
		}
		return nil
	})
	return session.Session, user.User, err
}

func (s *Store) ValidateCSRF(sessionToken, csrfToken string) error {
	var session storedSession
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketSessions), credentialKey(sessionToken), &session)
	})
	if err != nil {
		return err
	}
	if !session.ExpiresAt.After(s.now()) {
		return ErrExpired
	}
	if !secureEqualHash(csrfToken, session.CSRFHash) {
		return ErrInvalidCredentials
	}
	_, _, err = s.GetSession(sessionToken)
	return err
}

func (s *Store) TouchSession(raw string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := credentialKey(raw)
		var session storedSession
		if err := getJSON(tx.Bucket(bucketSessions), key, &session); err != nil {
			return err
		}
		if !session.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		session.LastSeenAt = s.now().UTC()
		return putJSON(tx.Bucket(bucketSessions), key, session)
	})
}

func (s *Store) RevokeSession(raw string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := []byte(credentialKey(raw))
		if tx.Bucket(bucketSessions).Get(key) == nil {
			return ErrNotFound
		}
		return tx.Bucket(bucketSessions).Delete(key)
	})
}

// RevokeUserSessions increments the account security version. Existing browser
// sessions and both kinds of bearer token immediately stop authenticating.
func (s *Store) RevokeUserSessions(userID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var user storedUser
		if err := getJSON(tx.Bucket(bucketUsers), userID, &user); err != nil {
			return err
		}
		user.SecurityVersion++
		user.UpdatedAt = s.now().UTC()
		return putJSON(tx.Bucket(bucketUsers), userID, user)
	})
}
