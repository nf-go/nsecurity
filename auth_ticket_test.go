// Copyright 2020 The nfgo Authors. All Rights Reserved.
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

	"github.com/stretchr/testify/assert"
)

func TestAuthTicketVerifySignature(t *testing.T) {
	signKey := "5f0fa825de41a7d3fd000002"
	ts := "1594800736455"
	subject := "admin"
	requestID := "xxx"
	token := "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjIyMjY3MTIzMDkuODY5ODM5Nywic3ViIjoiYWRtaW4iLCJ1c2VySWQiOjF9.2M1tC3oQrC0Ym7K9qfVVcLS-eyCM4bacVOyuh6Jj1yg"
	sig := "b7dc13da9157cdaf86e405063476c9a5dc2e677d420a06fd8195c9d3229cceba"

	ticket := &AuthTicket{
		Timestamp: ts,
		Subject:   subject,
		RequestID: requestID,
		Signature: sig,
		Token:     token,
	}

	assert.True(t, ticket.VerifySignature(signKey), "the signature should be valid")

	assert.NoError(t, ticket.VerifyToken("VoCra8#GEBAbRl*+vos9UF@??gi8Oy"))

}
