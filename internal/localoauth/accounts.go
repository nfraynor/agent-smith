package localoauth

import (
	"errors"

	bolt "go.etcd.io/bbolt"
)

// VerifyPassword performs the same bounded, constant-work verification used by
// login, addressed by immutable user ID for recent-password confirmation.
func (s *Store) VerifyPassword(userID, password string) error {
	var record storedUser
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		readErr := getJSON(tx.Bucket(bucketUsers), userID, &record)
		if errors.Is(readErr, ErrNotFound) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		found = true
		return nil
	})
	if err != nil {
		return err
	}
	encoded := s.dummyHash
	if found {
		encoded = record.PasswordHash
	}
	s.passwordSem <- struct{}{}
	valid, _ := verifyPassword(encoded, password)
	<-s.passwordSem
	if !found || !record.Enabled || !valid {
		return ErrInvalidCredentials
	}
	return nil
}

// ChangePassword verifies the current password, changes it atomically, clears
// the first-login flag, and invalidates all earlier sessions and tokens.
func (s *Store) ChangePassword(userID, currentPassword, newPassword string) error {
	if err := s.VerifyPassword(userID, currentPassword); err != nil {
		return err
	}
	newHash, err := hashPassword(newPassword, s.argon2)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		var record storedUser
		if err := getJSON(tx.Bucket(bucketUsers), userID, &record); err != nil {
			return err
		}
		if !record.Enabled {
			return ErrDisabled
		}
		// Verify again while holding the write transaction so a concurrent reset
		// cannot be overwritten after the first verification.
		s.passwordSem <- struct{}{}
		valid, _ := verifyPassword(record.PasswordHash, currentPassword)
		<-s.passwordSem
		if !valid {
			return ErrInvalidCredentials
		}
		record.PasswordHash = newHash
		record.MustChangePassword = false
		record.SecurityVersion++
		record.UpdatedAt = s.now().UTC()
		return putJSON(tx.Bucket(bucketUsers), userID, record)
	})
}
