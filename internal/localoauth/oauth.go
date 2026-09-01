package localoauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

func (s *Store) RegisterClient(registration ClientRegistration) (Client, error) {
	if strings.TrimSpace(registration.Name) == "" || len(registration.Name) > 128 {
		return Client{}, errors.New("client name is required and must not exceed 128 bytes")
	}
	if len(registration.RedirectURIs) == 0 || len(registration.RedirectURIs) > 10 {
		return Client{}, errors.New("client must have between one and ten redirect URIs")
	}
	seen := map[string]bool{}
	for _, uri := range registration.RedirectURIs {
		if uri == "" || len(uri) > 2048 || seen[uri] {
			return Client{}, errors.New("client redirect URIs must be non-empty and unique")
		}
		seen[uri] = true
	}
	id, err := randomToken()
	if err != nil {
		return Client{}, err
	}
	redirects := append([]string(nil), registration.RedirectURIs...)
	slices.Sort(redirects)
	now := s.now().UTC()
	var client Client
	err = s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketClients)
		count := 0
		if err := bucket.ForEach(func(_, value []byte) error {
			count++
			var existing Client
			if err := json.Unmarshal(value, &existing); err != nil {
				return fmt.Errorf("decode OAuth client: %w", err)
			}
			existingRedirects := append([]string(nil), existing.RedirectURIs...)
			slices.Sort(existingRedirects)
			if client.ID == "" && !existing.Disabled && existing.Source == registration.Source && slices.Equal(existingRedirects, redirects) {
				client = existing
			}
			return nil
		}); err != nil {
			return err
		}
		if client.ID != "" {
			return nil
		}
		if count >= 128 {
			return errors.New("dynamic client registration limit reached")
		}
		client = Client{ID: "cli_" + id, Name: registration.Name, RedirectURIs: redirects, Source: registration.Source, CreatedAt: now, UpdatedAt: now}
		return putJSON(bucket, client.ID, client)
	})
	return client, err
}

func (s *Store) GetClient(id string) (Client, error) {
	var client Client
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketClients), id, &client) })
	return client, err
}

func (s *Store) SetClientDisabled(id string, disabled bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		var client Client
		if err := getJSON(tx.Bucket(bucketClients), id, &client); err != nil {
			return err
		}
		client.Disabled, client.UpdatedAt = disabled, s.now().UTC()
		return putJSON(tx.Bucket(bucketClients), id, client)
	})
}

func (s *Store) CreateAuthorizationCode(grant AuthorizationGrant, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", errors.New("authorization code lifetime must be positive")
	}
	if grant.UserID == "" || grant.ClientID == "" || grant.RedirectURI == "" || grant.Resource == "" || grant.CodeChallenge == "" {
		return "", errors.New("authorization code bindings are required")
	}
	raw, err := randomToken()
	if err != nil {
		return "", err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := validateUserAndClient(tx, grant.UserID, grant.ClientID); err != nil {
			return err
		}
		record := storedCode{AuthorizationGrant: cloneAuthorizationGrant(grant), ExpiresAt: s.now().UTC().Add(ttl)}
		return putJSON(tx.Bucket(bucketCodes), credentialKey(raw), record)
	})
	return raw, err
}

func (s *Store) ConsumeAuthorizationCode(raw string, binding CodeBinding) (AuthorizationGrant, error) {
	var grant AuthorizationGrant
	var operationErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		key := credentialKey(raw)
		var record storedCode
		if err := getJSON(tx.Bucket(bucketCodes), key, &record); err != nil {
			operationErr = err
			return nil
		}
		if record.ConsumedAt != nil {
			operationErr = ErrConsumed
			return nil
		}
		if !record.ExpiresAt.After(s.now()) {
			operationErr = ErrExpired
			return tx.Bucket(bucketCodes).Delete([]byte(key))
		}
		if record.ClientID != binding.ClientID || record.RedirectURI != binding.RedirectURI || record.Resource != binding.Resource || record.CodeChallenge != binding.CodeChallenge {
			operationErr = ErrBindingMismatch
			return nil
		}
		if err := validateUserAndClient(tx, record.UserID, record.ClientID); err != nil {
			operationErr = err
			return nil
		}
		now := s.now().UTC()
		record.ConsumedAt = &now
		if err := putJSON(tx.Bucket(bucketCodes), key, record); err != nil {
			return err
		}
		grant = cloneAuthorizationGrant(record.AuthorizationGrant)
		return nil
	})
	if err != nil {
		return AuthorizationGrant{}, err
	}
	return grant, operationErr
}

func (s *Store) IssueTokenPair(grant TokenGrant, accessTTL, refreshTTL time.Duration) (TokenPair, error) {
	if accessTTL <= 0 || refreshTTL < 0 {
		return TokenPair{}, errors.New("access lifetime must be positive and refresh lifetime non-negative")
	}
	access, err := randomToken()
	if err != nil {
		return TokenPair{}, err
	}
	var refresh, family string
	if refreshTTL > 0 {
		refresh, err = randomToken()
		if err != nil {
			return TokenPair{}, err
		}
		family, err = randomToken()
		if err != nil {
			return TokenPair{}, err
		}
	}
	var pair TokenPair
	err = s.db.Update(func(tx *bolt.Tx) error {
		var user storedUser
		if err := getJSON(tx.Bucket(bucketUsers), grant.UserID, &user); err != nil {
			return err
		}
		if err := validateUserAndClient(tx, grant.UserID, grant.ClientID); err != nil {
			return err
		}
		pair, err = s.persistTokenPair(tx, grant, family, access, refresh, user.SecurityVersion, accessTTL, refreshTTL)
		return err
	})
	return pair, err
}

func (s *Store) RotateRefresh(raw string, binding RefreshBinding, accessTTL, refreshTTL time.Duration) (TokenPair, error) {
	if accessTTL <= 0 || refreshTTL <= 0 {
		return TokenPair{}, errors.New("token lifetimes must be positive")
	}
	access, err := randomToken()
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := randomToken()
	if err != nil {
		return TokenPair{}, err
	}
	var pair TokenPair
	var operationErr error
	err = s.db.Update(func(tx *bolt.Tx) error {
		key := credentialKey(raw)
		var current storedRefresh
		if err := getJSON(tx.Bucket(bucketRefresh), key, &current); err != nil {
			operationErr = err
			return nil
		}
		if current.ConsumedAt != nil {
			if err := revokeFamily(tx, current.FamilyID, s.now().UTC()); err != nil {
				return err
			}
			operationErr = ErrConsumed
			return nil
		}
		if current.RevokedAt != nil {
			operationErr = ErrRevoked
			return nil
		}
		if !current.ExpiresAt.After(s.now()) {
			operationErr = ErrExpired
			return nil
		}
		if current.ClientID != binding.ClientID || current.Resource != binding.Resource {
			operationErr = ErrBindingMismatch
			return nil
		}
		var user storedUser
		if err := getJSON(tx.Bucket(bucketUsers), current.UserID, &user); err != nil {
			operationErr = err
			return nil
		}
		if !user.Enabled {
			operationErr = ErrDisabled
			return nil
		}
		if current.SecurityVersion != user.SecurityVersion {
			operationErr = ErrRevoked
			return nil
		}
		var client Client
		if err := getJSON(tx.Bucket(bucketClients), current.ClientID, &client); err != nil {
			operationErr = err
			return nil
		}
		if client.Disabled {
			operationErr = ErrDisabled
			return nil
		}
		now := s.now().UTC()
		current.ConsumedAt = &now
		if err := putJSON(tx.Bucket(bucketRefresh), key, current); err != nil {
			return err
		}
		pair, err = s.persistTokenPair(tx, current.TokenGrant, current.FamilyID, access, refresh, user.SecurityVersion, accessTTL, refreshTTL)
		return err
	})
	if err != nil {
		return TokenPair{}, err
	}
	return pair, operationErr
}

func (s *Store) persistTokenPair(tx *bolt.Tx, grant TokenGrant, family, access, refresh string, securityVersion uint64, accessTTL, refreshTTL time.Duration) (TokenPair, error) {
	now := s.now().UTC()
	grant.Scopes = append([]string(nil), grant.Scopes...)
	accessRecord := storedAccess{TokenGrant: grant, ExpiresAt: now.Add(accessTTL), SecurityVersion: securityVersion}
	refreshRecord := storedRefresh{TokenGrant: grant, FamilyID: family, ExpiresAt: now.Add(refreshTTL), SecurityVersion: securityVersion}
	if err := putJSON(tx.Bucket(bucketAccess), credentialKey(access), accessRecord); err != nil {
		return TokenPair{}, err
	}
	if refresh != "" {
		if err := putJSON(tx.Bucket(bucketRefresh), credentialKey(refresh), refreshRecord); err != nil {
			return TokenPair{}, err
		}
	}
	pair := TokenPair{AccessToken: access, AccessExpiresAt: accessRecord.ExpiresAt}
	if refresh != "" {
		pair.RefreshToken, pair.RefreshExpiresAt = refresh, refreshRecord.ExpiresAt
	}
	return pair, nil
}

func (s *Store) AuthenticateAccess(raw, resource string) (AccessGrant, error) {
	var record storedAccess
	var user storedUser
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := getJSON(tx.Bucket(bucketAccess), credentialKey(raw), &record); err != nil {
			return err
		}
		if record.RevokedAt != nil {
			return ErrRevoked
		}
		if !record.ExpiresAt.After(s.now()) {
			return ErrExpired
		}
		if record.Resource != resource {
			return ErrBindingMismatch
		}
		if err := getJSON(tx.Bucket(bucketUsers), record.UserID, &user); err != nil {
			return err
		}
		if !user.Enabled {
			return ErrDisabled
		}
		if record.SecurityVersion != user.SecurityVersion {
			return ErrRevoked
		}
		var client Client
		if err := getJSON(tx.Bucket(bucketClients), record.ClientID, &client); err != nil {
			return err
		}
		if client.Disabled {
			return ErrDisabled
		}
		return nil
	})
	if err != nil {
		return AccessGrant{}, err
	}
	return AccessGrant{User: user.User, ClientID: record.ClientID, Resource: record.Resource, Scopes: append([]string(nil), record.Scopes...), ExpiresAt: record.ExpiresAt}, nil
}

func (s *Store) RevokeToken(raw, clientID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := credentialKey(raw)
		var access storedAccess
		if err := getJSON(tx.Bucket(bucketAccess), key, &access); err == nil {
			if access.ClientID != clientID {
				return ErrBindingMismatch
			}
			now := s.now().UTC()
			access.RevokedAt = &now
			return putJSON(tx.Bucket(bucketAccess), key, access)
		}
		var refresh storedRefresh
		if err := getJSON(tx.Bucket(bucketRefresh), key, &refresh); err != nil {
			return nil
		} // RFC 7009 hides unknown tokens.
		if refresh.ClientID != clientID {
			return ErrBindingMismatch
		}
		return revokeFamily(tx, refresh.FamilyID, s.now().UTC())
	})
}

func revokeFamily(tx *bolt.Tx, family string, now time.Time) error {
	bucket := tx.Bucket(bucketRefresh)
	return bucket.ForEach(func(key, value []byte) error {
		var record storedRefresh
		if err := jsonUnmarshal(value, &record); err != nil {
			return err
		}
		if record.FamilyID != family {
			return nil
		}
		record.RevokedAt = &now
		return putJSON(bucket, string(key), record)
	})
}

func (s *Store) CleanupExpired() error {
	now := s.now()
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, item := range []struct {
			bucket  []byte
			expired func([]byte) (bool, error)
		}{
			{bucketSessions, func(value []byte) (bool, error) {
				var v storedSession
				e := jsonUnmarshal(value, &v)
				return !v.ExpiresAt.After(now), e
			}},
			{bucketCodes, func(value []byte) (bool, error) {
				var v storedCode
				e := jsonUnmarshal(value, &v)
				return !v.ExpiresAt.After(now), e
			}},
			{bucketAccess, func(value []byte) (bool, error) {
				var v storedAccess
				e := jsonUnmarshal(value, &v)
				return !v.ExpiresAt.After(now), e
			}},
			{bucketRefresh, func(value []byte) (bool, error) {
				var v storedRefresh
				e := jsonUnmarshal(value, &v)
				return !v.ExpiresAt.After(now), e
			}},
		} {
			bucket := tx.Bucket(item.bucket)
			cursor := bucket.Cursor()
			for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
				expired, err := item.expired(value)
				if err != nil {
					return err
				}
				if expired {
					if err = cursor.Delete(); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func validateUserAndClient(tx *bolt.Tx, userID, clientID string) error {
	var user storedUser
	if err := getJSON(tx.Bucket(bucketUsers), userID, &user); err != nil {
		return err
	}
	if !user.Enabled {
		return ErrDisabled
	}
	var client Client
	if err := getJSON(tx.Bucket(bucketClients), clientID, &client); err != nil {
		return err
	}
	if client.Disabled {
		return ErrDisabled
	}
	return nil
}

func cloneAuthorizationGrant(grant AuthorizationGrant) AuthorizationGrant {
	grant.Scopes = append([]string(nil), grant.Scopes...)
	return grant
}

func jsonUnmarshal(value []byte, target any) error { return json.Unmarshal(value, target) }
