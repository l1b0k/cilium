// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//+build ipam_provider_alibabacloud

package main

import (
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/pkg/option"
)

func init() {
	flags := rootCmd.Flags()

	flags.String(operatorOption.AlibabaCloudVpcID, "", "Specific vpc ID for AlibabaCloud ENI. If not set use same vpc as operator")
	option.BindEnv(operatorOption.AlibabaCloudVpcID)

	flags.Bool(operatorOption.AlibabaCloudUsePrimaryENI, false, "Allows alloc ip from primary eni.Default false ,only use secondary eni")
	option.BindEnv(operatorOption.AlibabaCloudUsePrimaryENI)

	viper.BindPFlags(flags)
}
