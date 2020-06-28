// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2020 Octabase Blockchain Labs.

package zamane

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// AuthToken is used to authenticate requests to Zamane servers.
type AuthToken struct {
	UserID         int    // customer number used in KamuSM
	Salt           []byte // a cryptorandom value to derive AES key
	IterationCount int    // PBKDF2 iteration count
	IV             []byte // initial vector to encrypt the payload
	Ciphertext     []byte // encrypted payload that must be part of the request
}

// ErrInvalidAuthentication indicates the auth token is can not be authorized.
var ErrInvalidAuthentication = errors.New("authentication token is not valid")

const (
	kamusmKDIter = 100          // this value is used by the tss client of KamuSM
	minKDIter    = kamusmKDIter //
	maxKDIter    = 1 << 17      // took around 100 ms on commodity hardware
	minSaltLen   = 8            // it is defined in the RFC2898

	maxSaltLen       = 1 << 8
	maxCiphertextLen = 512/8 + aes.BlockSize                                      // max payload is the same as padded output length of SHA-512
	maxWireLen       = 16 + 4 + maxSaltLen + 4 + aes.BlockSize + maxCiphertextLen // asn1enc+uid+salt+iter+iv+ciphertext
)

// NewAuthToken builds a token to prove that client knows the user credentials.
// AuthToken has also the binding property with the payload which can be a part of the request.
func NewAuthToken(rand io.Reader, customerID int, password string, payload []byte) (*AuthToken, error) {
	// KamuSM's tss client uses 8-byte salt, but we prefer a more reasonable
	// value instead, same as the block size of the hash will use.
	salt := make([]byte, 256/8)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, err
	}

	// use a reasonable value to iterate.
	iter := maxKDIter / 4

	// derive an AES-256 key by the user password to encrypt the payload.
	key := pbkdf2.Key([]byte(password), salt, iter, 256/8, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	initVector := make([]byte, aes.BlockSize)
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
func (r *AuthToken) Verify(rand io.Reader, password string, payload []byte) error {
	if r.IterationCount < minKDIter {
		return errors.New("insufficient iteration to derive cipher key")
	}

	// too many iterations can allow denial-of-service attacks
	if r.IterationCount > maxKDIter {
		return errors.New("exceeds the maximum number of iteration")
	}

	if len(r.Salt) > maxSaltLen {
		return errors.New("salt value is too long")
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

	if len(r.Ciphertext) > maxCiphertextLen {
		return errors.New("ciphertext value is too long")
	}

	if len(r.Ciphertext)%aes.BlockSize != 0 {
		return errors.New("malformed ciphertext value")
	}

	cleartext := make([]byte, paddedLen(len(r.Ciphertext), block.BlockSize()))

	cbc := cipher.NewCBCDecrypter(block, r.IV)
	cbc.CryptBlocks(cleartext, r.Ciphertext)

	expectedPayload := padded(payload[:], block.BlockSize())

	if ok := 1 == subtle.ConstantTimeCompare(expectedPayload, cleartext); !ok {
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

// following padding algorithm is compatible with PKCS#5 and PKCS#7.
// if the len is equal to blocksize it returns len+blocksize to
// distinguish padded bytes.
func paddedLen(len, blockSize int) int {
	return len + blockSize - len%blockSize
}

func padded(input []byte, blockSize int) []byte {
	plen := paddedLen(len(input), blockSize)
	padded := bytes.Repeat([]byte{byte(plen - len(input))}, plen)

	copy(padded, input)

	return padded
}
