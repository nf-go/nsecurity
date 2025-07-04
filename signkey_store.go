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
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/nf-go/nfgo/ndb"
	"github.com/nf-go/nfgo/nutil/ntypes"
)

const (
	// RedisKeySignKey - nfgo:signkey:{appType}:{subject}
	RedisKeySignKey ntypes.Key = "nfgo:signkey:%s:%s"
)

// SignKeyStore -
type SignKeyStore interface {
	Store(clientType, subject, signKey string) error
	Get(clientType, subject string) (string, error)
}

// NewRedisSignKeyStore -
func NewRedisSignKeyStore(redisOper ndb.RedisOper, securityConfig *SecurityConfig) SignKeyStore {
	return &redisSignKeyStore{
		redisOper:      redisOper,
		securityConfig: securityConfig,
	}
}

// redisSignKeyStore -
type redisSignKeyStore struct {
	redisOper      ndb.RedisOper
	securityConfig *SecurityConfig
}

func (s *redisSignKeyStore) Store(clientType, subject, signKey string) error {
	key := RedisKeySignKey.String(clientType, subject)
	return s.redisOper.SetStringOpts(key, signKey, false, false, s.securityConfig.SignKeyLifeTime)
}

func (s *redisSignKeyStore) Get(clientType, subject string) (signKey string, err error) {
	conn := s.redisOper.Conn()
	//nolint:errcheck
	defer conn.Close()

	signKeyRedisKey := RedisKeySignKey.String(clientType, subject)
	if s.securityConfig.RefreshSignKeyLife {
		if err = conn.Send("EXPIRE", signKeyRedisKey, int64(s.securityConfig.SignKeyLifeTime/time.Second)); err != nil {
			return
		}
		if err = conn.Send("GET", signKeyRedisKey); err != nil {
			return
		}
		if err = conn.Flush(); err != nil {
			return
		}
		if _, err = conn.Receive(); err != nil {
			return
		}
		signKey, err = redis.String(conn.Receive())
	} else {
		signKey, err = redis.String(conn.Do("GET", signKeyRedisKey))
	}

	if err == redis.ErrNil {
		return "", nil
	}

	return
}
