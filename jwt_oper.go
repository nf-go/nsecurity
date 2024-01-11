// Copyright 2023 The nfgo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nsecurity

import (
	"crypto/ed25519"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"time"

	"github.com/nf-go/nfgo/nlog"
	"github.com/pascaldekloe/jwt"
)

type JWTOper interface {
	IssueToken(subject string, expiration time.Time, set map[string]interface{}) (string, error)

	ParseToken(token string) (*JWTPayload, error)

	ValidateToken(token string) (*JWTPayload, error)
}

func MustNewJWTOper(config *SecurityConfig) JWTOper {
	oper, err := NewJWTOper(config)
	if err != nil {
		nlog.Fatal("fail to new JWTOper: ", err)
	}
	return oper
}

func NewJWTOper(config *SecurityConfig) (JWTOper, error) {
	return newJWTEdDSAOper(config)
}

type JWTPayload struct {
	Subject string
	Expires time.Time
	Set     map[string]interface{}
}

func newJWTPayload(claims *jwt.Claims) *JWTPayload {
	return &JWTPayload{
		Subject: claims.Subject,
		Expires: claims.Expires.Time(),
		Set:     claims.Set,
	}
}

type jwtEdDSAOper struct {
	jwtConfig         *JWTConfig
	ed25519PrivateKey ed25519.PrivateKey
	ed25519PublicKey  ed25519.PublicKey
}

func newJWTEdDSAOper(config *SecurityConfig) (*jwtEdDSAOper, error) {
	jwtConfig := config.JWT

	block, _ := pem.Decode([]byte(jwtConfig.JWTPrivateKey))
	var ed25519PrivateKey ed25519PrivKey
	_, err := asn1.Unmarshal(block.Bytes, &ed25519PrivateKey)
	if err != nil {
		return nil, err
	}

	block, _ = pem.Decode([]byte(jwtConfig.JWTPublicKey))
	var ed25519PublicKey ed25519PubKey
	_, err = asn1.Unmarshal(block.Bytes, &ed25519PublicKey)
	if err != nil {
		return nil, err
	}

	return &jwtEdDSAOper{
		jwtConfig:         jwtConfig,
		ed25519PrivateKey: ed25519.NewKeyFromSeed(ed25519PrivateKey.PrivateKey[2:]),
		ed25519PublicKey:  ed25519.PublicKey(ed25519PublicKey.PublicKey.Bytes),
	}, nil
}

type ed25519PrivKey struct {
	Version          int
	ObjectIdentifier struct {
		ObjectIdentifier asn1.ObjectIdentifier
	}
	PrivateKey []byte
}

type ed25519PubKey struct {
	OBjectIdentifier struct {
		ObjectIdentifier asn1.ObjectIdentifier
	}
	PublicKey asn1.BitString
}

func (o *jwtEdDSAOper) IssueToken(subject string, expiration time.Time, set map[string]interface{}) (string, error) {
	claims := jwt.Claims{}
	claims.Subject = subject
	claims.Expires = jwt.NewNumericTime(expiration)
	claims.Set = set
	token, err := claims.EdDSASign(o.ed25519PrivateKey)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func (o *jwtEdDSAOper) ParseToken(token string) (*JWTPayload, error) {
	claims, err := jwt.EdDSACheck([]byte(token), o.ed25519PublicKey)
	if err != nil {
		return nil, err
	}
	return newJWTPayload(claims), nil
}

func (o *jwtEdDSAOper) ValidateToken(token string) (*JWTPayload, error) {
	claims, err := jwt.EdDSACheck([]byte(token), o.ed25519PublicKey)
	if err != nil {
		return nil, err
	}
	if valid := claims.Valid(time.Now()); !valid {
		return nil, errors.New("token is expired")
	}
	return newJWTPayload(claims), nil
}
