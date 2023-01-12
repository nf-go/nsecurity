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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	// openssl genpkey -algorithm Ed25519  --out private.pem
	jwtPrivateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOrrk4Ec73oaJ6c/N+A5QIf9WaIgIOEO9dxaEBbQUts6
-----END PRIVATE KEY-----
`
	// openssl pkey -in private.pem -pubout --out public.pem
	jwtPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJLaXDs6JySsqlLu6iEvdXU9TBXdKbl21naMSMTTxHTs=
-----END PUBLIC KEY-----	
`
)

func newSecurityConfig() *SecurityConfig {
	return &SecurityConfig{JWT: &JWTConfig{
		JWTPrivateKey: jwtPrivateKey,
		JWTPublicKey:  jwtPublicKey,
	}}
}

func TestNewJWTOper(t *testing.T) {
	a := assert.New(t)

	oper, err := NewJWTOper(newSecurityConfig())
	a.NoError(err)
	a.NotNil(oper)
}

func TestMustNewJWTOper(t *testing.T) {
	a := assert.New(t)

	oper := MustNewJWTOper(newSecurityConfig())
	a.NotNil(oper)
}

func Test_jwtOper_IssueToken(t *testing.T) {
	a := assert.New(t)

	oper := MustNewJWTOper(newSecurityConfig())
	a.NotNil(oper)

	token, err := oper.IssueToken("admin", time.Now().Add(time.Hour*24*365*20), map[string]interface{}{"userId": 1})
	a.NoError(err)
	t.Log(token)
	a.NotEmpty(token)
}

func Test_jwtOper_ParseToken(t *testing.T) {
	a := assert.New(t)

	oper := MustNewJWTOper(newSecurityConfig())
	a.NotNil(oper)

	token, err := oper.IssueToken("admin", time.Now().Add(time.Hour*24*365*20), map[string]interface{}{"userId": 1})
	a.NoError(err)
	a.NotEmpty(token)

	payload, err := oper.ParseToken(token)
	a.NoError(err)
	a.Equal("admin", payload.Subject)
	a.True(time.Until(payload.Expires) > 0)
	a.Equal(float64(1), payload.Set["userId"])

}

func Test_jwtOper_ValidateToken(t *testing.T) {
	a := assert.New(t)

	oper := MustNewJWTOper(newSecurityConfig())
	a.NotNil(oper)

	token, err := oper.IssueToken("admin", time.Now().Add(-time.Hour), map[string]interface{}{"userId": 1})
	a.NoError(err)
	a.NotEmpty(token)

	playload, err := oper.ValidateToken(token)
	t.Log(err)
	a.Error(err)
	a.Nil(playload)

}
