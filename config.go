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

import "time"

// SecurityConfig -
type SecurityConfig struct {
	SignKeyLifeTime    time.Duration `yaml:"signKeyLifeTime"`
	RefreshSignKeyLife bool          `yaml:"refreshSignKeyLife"`
	TimeWindow         time.Duration `yaml:"timeWindow"`
	Anons              []string      `yaml:"anons"`
	Model              string        `yaml:"model"`
	Policies           []string      `yaml:"policies"`
}

// SetDefaultValues -
func (conf *SecurityConfig) SetDefaultValues() {
	if conf.TimeWindow == 0 {
		conf.TimeWindow = 30 * time.Minute
	}
	if conf.SignKeyLifeTime == 0 {
		conf.SignKeyLifeTime = 365 * 24 * time.Hour
	}
}
