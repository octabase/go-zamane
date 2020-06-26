// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2020 Octabase Blockchain Labs.

package zamane

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// AuthToken is used to authenticate requests to Zamane servers,
// includes a mechanism to prevent replay attacks.
type AuthToken struct {
	UserID         int    // customer number used in KamuSM
	Salt           []byte // an 8-byte cryptorandom value to derive AES key
	IterationCount int    // PBKDF2 iteration count
	IV             []byte // initial vector to encrypt the payload
	Ciphertext     []byte // it's equal to aes256cbc(padding(sha1(str(customerNumber) + str(epochInMillis))))
}

// ErrInvalidAuthentication indicates the auth token is can not be authorized
var ErrInvalidAuthentication = errors.New("authentication token is not valid")

const (
	kamusmKDIter = 100
	minKDIter    = kamusmKDIter
	maxKDIter    = 1 << 17 // took around 100 ms on commodity hardware
	minSaltLen   = 8       // it is defined in the RFC2898
	maxWireLen   = 10 * ((aes.BlockSize * 2) + minSaltLen + 8)
)

// NewAuthToken ...
func NewAuthToken(rand io.Reader, timestamp time.Time, customerID int, password string) (*AuthToken, error) {
	epoch := int(timestamp.UnixNano() / int64(time.Millisecond))

	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, err
	}

	payload := sha1.Sum([]byte(strconv.Itoa(customerID) + strconv.Itoa(epoch)))

	iter := kamusmKDIter

	key := pbkdf2.Key([]byte(password), salt, iter, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	initVector := make([]byte, 16)
	if _, err := io.ReadFull(rand, initVector); err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, initVector)

	ciphertext := make([]byte, paddedLen(len(payload), block.BlockSize()))

	cbc.CryptBlocks(ciphertext, padded(payload[:], block.BlockSize()))

	return &AuthToken{
		UserID:         customerID,
		Salt:           salt,
		IterationCount: iter,
		IV:             initVector,
		Ciphertext:     ciphertext,
	}, nil
}

// Verify checks authentication of the token with the given password and timestamp.
func (r *AuthToken) Verify(rand io.Reader, timestamp time.Time, password string) error {
	epoch := int(timestamp.UnixNano() / int64(time.Millisecond))

	if r.IterationCount < minKDIter {
		return errors.New("insufficient iteration to derive cipher key")
	}

	// take care of denial-of-service attacks
	if r.IterationCount > maxKDIter {
		return errors.New("exceeds the maximum number of iteration")
	}

	key := pbkdf2.Key([]byte(password), r.Salt, r.IterationCount, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(r.IV) != block.BlockSize() {
		return errors.New("illegal value of the initial vector")
	}

	if len(r.Salt) < minSaltLen {
		return errors.New("insufficient amount of salt")
	}

	payload := make([]byte, paddedLen(len(r.Ciphertext), block.BlockSize()))

	cbc := cipher.NewCBCDecrypter(block, r.IV)
	cbc.CryptBlocks(payload, r.Ciphertext)

	tmp := sha1.Sum([]byte(strconv.Itoa(r.UserID) + strconv.Itoa(epoch)))
	expectedPayload := padded(tmp[:], block.BlockSize())

	if ok := 1 == subtle.ConstantTimeCompare(expectedPayload, payload); !ok {
		return ErrInvalidAuthentication
	}

	return nil
}

// MarshalASN1 returns the ASN.1 encoding of the token.
func (r *AuthToken) MarshalASN1() ([]byte, error) {
	buf := &bytes.Buffer{}

	el, err := asn1.Marshal(r.UserID)
	if err != nil {
		return nil, err
	}
	buf.Write(el)

	el, err = asn1.Marshal(r.Salt)
	if err != nil {
		return nil, err
	}
	buf.Write(el)

	el, err = asn1.Marshal(r.IterationCount)
	if err != nil {
		return nil, err
	}
	buf.Write(el)

	el, err = asn1.Marshal(r.IV)
	if err != nil {
		return nil, err
	}
	buf.Write(el)

	el, err = asn1.Marshal(r.Ciphertext)
	if err != nil {
		return nil, err
	}
	buf.Write(el)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      buf.Bytes(),
	})
}

// UnmarshalASN1 parses the DER-encoded ASN.1 data structure into the token.
func (r *AuthToken) UnmarshalASN1(data []byte) (err error) {
	var raw asn1.RawValue

	if len(data) > maxWireLen {
		return errors.New("asn.1 input is too long")
	}

	if _, err = asn1.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.Tag != asn1.TagSequence {
		return errors.New("asn.1 input is must be sequence")
	}

	if data, err = asn1.Unmarshal(raw.Bytes, &r.UserID); err != nil {
		return err
	}

	if data, err = asn1.Unmarshal(data, &r.Salt); err != nil {
		return err
	}

	if data, err = asn1.Unmarshal(data, &r.IterationCount); err != nil {
		return err
	}

	if data, err = asn1.Unmarshal(data, &r.IV); err != nil {
		return err
	}

	if data, err = asn1.Unmarshal(data, &r.Ciphertext); err != nil {
		return err
	}

	return nil
}

func paddedLen(len, blockSize int) int {
	m := len % blockSize
	if m == 0 {
		return len
	}

	return len + blockSize - m
}

func padded(input []byte, blockSize int) []byte {
	plen := paddedLen(len(input), blockSize)
	padded := bytes.Repeat([]byte{byte(plen - len(input))}, plen)

	copy(padded, input)

	return padded
}
