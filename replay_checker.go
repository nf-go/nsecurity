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
	"github.com/nf-go/nfgo/nerrors"
	"github.com/nf-go/nfgo/nutil/ntypes"
)

const (
	// RedisKeyRequestID - nfgo:reqid:{requestID}
	RedisKeyRequestID ntypes.Key = "nfgo:reqid:%s"
)

// ReplayChecker -
type ReplayChecker interface {
	VerifyReplay(requestID string) error
}

// NewRedisReplayChecker -
func NewRedisReplayChecker(redisOper ndb.RedisOper, securityConfig *SecurityConfig) ReplayChecker {
	return &redisReplayChecker{
		redisOper:      redisOper,
		securityConfig: securityConfig,
	}
}

type redisReplayChecker struct {
	redisOper      ndb.RedisOper
	securityConfig *SecurityConfig
}

func (r *redisReplayChecker) VerifyReplay(requestID string) error {
	conn := r.redisOper.Conn()
	//nolint:errcheck
	defer conn.Close()

	ttl := int64(r.securityConfig.TimeWindow / time.Second)
	_, err := redis.String(conn.Do("SET", RedisKeyRequestID.String(requestID), "1", "EX", ttl, "NX"))
	if err == redis.ErrNil {
		return nerrors.ErrUnauthorized
	}
	if err != nil {
		return err
	}
	return nil
}
