package localoauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nfraynor/agent-smith/internal/permissions"
	bolt "go.etcd.io/bbolt"
)

const schemaVersion = 1

var (
	bucketMeta       = []byte("meta")
	bucketUsers      = []byte("users")
	bucketEmails     = []byte("emails")
	bucketClients    = []byte("clients")
	bucketSessions   = []byte("sessions")
	bucketCodes      = []byte("codes")
	bucketAccess     = []byte("access_tokens")
	bucketRefresh    = []byte("refresh_tokens")
	keySchemaVersion = []byte("schema_version")
)

type Store struct {
	db          *bolt.DB
	now         func() time.Time
	argon2      Argon2Params
	passwordSem chan struct{}
	dummyHash   string
}

type storedUser struct {
	User
	PasswordHash string `json:"password_hash"`
}
type storedSession struct {
	Session
	CSRFHash string `json:"csrf_hash"`
}
type storedCode struct {
	AuthorizationGrant
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}
type storedAccess struct {
	TokenGrant
	ExpiresAt       time.Time  `json:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	SecurityVersion uint64     `json:"security_version"`
}
type storedRefresh struct {
	TokenGrant
	FamilyID        string     `json:"family_id"`
	ExpiresAt       time.Time  `json:"expires_at"`
	ConsumedAt      *time.Time `json:"consumed_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	SecurityVersion uint64     `json:"security_version"`
}

func Open(options Options) (*Store, error) {
	if strings.TrimSpace(options.Path) == "" {
		return nil, errors.New("OAuth data file path is required")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Argon2 == (Argon2Params{}) {
		options.Argon2 = DefaultArgon2Params()
	}
	if err := validateArgon2(options.Argon2); err != nil {
		return nil, err
	}
	if options.PasswordConcurrency <= 0 {
		options.PasswordConcurrency = 2
	}
	if options.PasswordConcurrency > 32 {
		return nil, errors.New("password concurrency must not exceed 32")
	}
	absolute, err := filepath.Abs(options.Path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(absolute)
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create OAuth data directory: %w", err)
	}
	if err = os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure OAuth data directory: %w", err)
	}
	db, err := bolt.Open(absolute, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoGrowSync: false})
	if err != nil {
		return nil, fmt.Errorf("open OAuth data store: %w", err)
	}
	if err = os.Chmod(absolute, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure OAuth data store: %w", err)
	}
	store := &Store{db: db, now: options.Now, argon2: options.Argon2, passwordSem: make(chan struct{}, options.PasswordConcurrency)}
	store.dummyHash, err = hashPassword("remoteops-constant-work-password", options.Argon2)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketMeta, bucketUsers, bucketEmails, bucketClients, bucketSessions, bucketCodes, bucketAccess, bucketRefresh} {
			if _, createErr := tx.CreateBucketIfNotExists(name); createErr != nil {
				return createErr
			}
		}
		meta := tx.Bucket(bucketMeta)
		version := meta.Get(keySchemaVersion)
		if version == nil {
			return meta.Put(keySchemaVersion, []byte{schemaVersion})
		}
		if len(version) != 1 || int(version[0]) != schemaVersion {
			return fmt.Errorf("unsupported OAuth schema version %v", version)
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Bootstrap(email, password string, role permissions.Role) (User, bool, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		return User{}, false, err
	}
	if err = validateRole(role); err != nil {
		return User{}, false, err
	}
	var result User
	created := false
	err = s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketUsers).Cursor()
		_, value := cursor.First()
		if value == nil {
			return nil
		}
		var existing storedUser
		if decodeErr := json.Unmarshal(value, &existing); decodeErr != nil {
			return decodeErr
		}
		result = existing.User
		return ErrAlreadyExists
	})
	if errors.Is(err, ErrAlreadyExists) {
		return result, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	hash, err := hashPassword(password, s.argon2)
	if err != nil {
		return User{}, false, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if key, _ := tx.Bucket(bucketUsers).Cursor().First(); key != nil {
			return ErrAlreadyExists
		}
		now := s.now().UTC()
		id, tokenErr := randomToken()
		if tokenErr != nil {
			return tokenErr
		}
		result = User{ID: "usr_" + id, Email: normalized, Role: role, Enabled: true, MustChangePassword: true, SecurityVersion: 1, CreatedAt: now, UpdatedAt: now}
		if putErr := putJSON(tx.Bucket(bucketUsers), result.ID, storedUser{User: result, PasswordHash: hash}); putErr != nil {
			return putErr
		}
		if putErr := tx.Bucket(bucketEmails).Put([]byte(normalized), []byte(result.ID)); putErr != nil {
			return putErr
		}
		created = true
		return nil
	})
	if errors.Is(err, ErrAlreadyExists) {
		user, getErr := s.firstUser()
		return user, false, getErr
	}
	return result, created, err
}

func (s *Store) CreateUser(email, password string, role permissions.Role, mustChange bool) (User, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if err = validateRole(role); err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password, s.argon2)
	if err != nil {
		return User{}, err
	}
	var user User
	err = s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketEmails).Get([]byte(normalized)) != nil {
			return ErrAlreadyExists
		}
		id, tokenErr := randomToken()
		if tokenErr != nil {
			return tokenErr
		}
		now := s.now().UTC()
		user = User{ID: "usr_" + id, Email: normalized, Role: role, Enabled: true, MustChangePassword: mustChange, SecurityVersion: 1, CreatedAt: now, UpdatedAt: now}
		if putErr := putJSON(tx.Bucket(bucketUsers), user.ID, storedUser{User: user, PasswordHash: hash}); putErr != nil {
			return putErr
		}
		return tx.Bucket(bucketEmails).Put([]byte(normalized), []byte(user.ID))
	})
	return user, err
}

func (s *Store) Authenticate(email, password string) (User, error) {
	normalized, normalizeErr := normalizeEmail(email)
	var record storedUser
	found := false
	var lookupErr error
	if normalizeErr == nil {
		lookupErr = s.db.View(func(tx *bolt.Tx) error {
			id := tx.Bucket(bucketEmails).Get([]byte(normalized))
			if id == nil {
				return nil
			}
			if err := getJSON(tx.Bucket(bucketUsers), string(id), &record); err != nil {
				return err
			}
			found = true
			return nil
		})
	}
	if lookupErr != nil {
		return User{}, lookupErr
	}
	encoded := s.dummyHash
	if found {
		encoded = record.PasswordHash
	}
	s.passwordSem <- struct{}{}
	valid, oldParams := verifyPassword(encoded, password)
	<-s.passwordSem
	if !found || !valid || !record.Enabled {
		return User{}, ErrInvalidCredentials
	}
	if !sameArgon2(oldParams, s.argon2) {
		newHash, err := hashPassword(password, s.argon2)
		if err != nil {
			return User{}, err
		}
		err = s.db.Update(func(tx *bolt.Tx) error {
			var current storedUser
			if err := getJSON(tx.Bucket(bucketUsers), record.ID, &current); err != nil {
				return err
			}
			if current.PasswordHash != record.PasswordHash {
				return nil
			}
			current.PasswordHash = newHash
			return putJSON(tx.Bucket(bucketUsers), current.ID, current)
		})
		if err != nil {
			return User{}, err
		}
	}
	return record.User, nil
}

func (s *Store) GetUser(id string) (User, error) {
	var record storedUser
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketUsers), id, &record) })
	return record.User, err
}

func (s *Store) ListUsers() ([]User, error) {
	var users []User
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).ForEach(func(_, value []byte) error {
			var record storedUser
			if err := json.Unmarshal(value, &record); err != nil {
				return err
			}
			users = append(users, record.User)
			return nil
		})
	})
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
	return users, err
}

func (s *Store) UpdateUser(id string, update UserUpdate) (User, error) {
	var result User
	err := s.db.Update(func(tx *bolt.Tx) error {
		var record storedUser
		if err := getJSON(tx.Bucket(bucketUsers), id, &record); err != nil {
			return err
		}
		if update.Role != nil {
			if err := validateRole(*update.Role); err != nil {
				return err
			}
			record.Role = *update.Role
		}
		if update.Enabled != nil {
			record.Enabled = *update.Enabled
		}
		if update.MustChangePassword != nil {
			record.MustChangePassword = *update.MustChangePassword
		}
		record.SecurityVersion++
		record.UpdatedAt = s.now().UTC()
		result = record.User
		return putJSON(tx.Bucket(bucketUsers), id, record)
	})
	return result, err
}

func (s *Store) ResetPassword(id, password string, mustChange bool) error {
	hash, err := hashPassword(password, s.argon2)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		var record storedUser
		if err := getJSON(tx.Bucket(bucketUsers), id, &record); err != nil {
			return err
		}
		record.PasswordHash = hash
		record.MustChangePassword = mustChange
		record.SecurityVersion++
		record.UpdatedAt = s.now().UTC()
		return putJSON(tx.Bucket(bucketUsers), id, record)
	})
}

func (s *Store) firstUser() (User, error) {
	var user storedUser
	err := s.db.View(func(tx *bolt.Tx) error {
		_, value := tx.Bucket(bucketUsers).Cursor().First()
		if value == nil {
			return ErrNotFound
		}
		return json.Unmarshal(value, &user)
	})
	return user.User, err
}

func normalizeEmail(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || strings.ContainsAny(value, "\r\n") || len(value) > 254 {
		return "", errors.New("a valid bare email address is required")
	}
	parts := strings.Split(parsed.Address, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("a valid email address is required")
	}
	return strings.ToLower(parsed.Address), nil
}

func validateRole(role permissions.Role) error {
	_, err := permissions.ParseRole(string(role))
	return err
}

func randomToken() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func credentialKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func getJSON(bucket *bolt.Bucket, key string, target any) error {
	value := bucket.Get([]byte(key))
	if value == nil {
		return ErrNotFound
	}
	if err := json.Unmarshal(value, target); err != nil {
		return fmt.Errorf("decode OAuth record: %w", err)
	}
	return nil
}

func putJSON(bucket *bolt.Bucket, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return bucket.Put([]byte(key), data)
}

func secureEqualHash(raw, encoded string) bool {
	candidate := credentialKey(raw)
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(encoded)) == 1
}
