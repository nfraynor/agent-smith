package localoauth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

func validateArgon2(params Argon2Params) error {
	if params.MemoryKiB < 16*1024 || params.MemoryKiB > 256*1024 || params.Iterations < 1 || params.Iterations > 10 || params.Parallelism < 1 || params.Parallelism > 16 || params.SaltBytes < 16 || params.SaltBytes > 64 || params.KeyBytes < 16 || params.KeyBytes > 64 {
		return errors.New("Argon2id parameters are outside safe bounds")
	}
	return nil
}

func hashPassword(password string, params Argon2Params) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("password must be between 12 and 1024 bytes")
	}
	salt := make([]byte, params.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, params.KeyBytes)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", params.MemoryKiB, params.Iterations, params.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(encoded, password string) (bool, Argon2Params) {
	params, salt, expected, err := parsePasswordHash(encoded)
	if err != nil {
		return false, Argon2Params{}
	}
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.MemoryKiB, params.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, params
}

func parsePasswordHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2Params{}, nil, nil, errors.New("invalid password hash")
	}
	var p Argon2Params
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return p, nil, nil, errors.New("invalid password parameters")
	}
	memory, err := parseUintField(fields[0], "m=")
	if err != nil {
		return p, nil, nil, err
	}
	iterations, err := parseUintField(fields[1], "t=")
	if err != nil {
		return p, nil, nil, err
	}
	parallelism, err := parseUintField(fields[2], "p=")
	if err != nil || parallelism > 255 {
		return p, nil, nil, errors.New("invalid password parameters")
	}
	p.MemoryKiB, p.Iterations, p.Parallelism = uint32(memory), uint32(iterations), uint8(parallelism)
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, err
	}
	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, err
	}
	p.SaltBytes, p.KeyBytes = uint32(len(salt)), uint32(len(hash))
	if err = validateArgon2(p); err != nil {
		return p, nil, nil, err
	}
	return p, salt, hash, nil
}

func parseUintField(value, prefix string) (uint64, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, errors.New("invalid password parameters")
	}
	return strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
}

func sameArgon2(a, b Argon2Params) bool {
	return a.MemoryKiB == b.MemoryKiB && a.Iterations == b.Iterations && a.Parallelism == b.Parallelism && a.SaltBytes == b.SaltBytes && a.KeyBytes == b.KeyBytes
}
