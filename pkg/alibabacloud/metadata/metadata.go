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

package metadata

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const (
	metadataURL = "http://100.100.100.200/latest/meta-data"
)

// GetInstanceID return instance ID form metadata
func GetInstanceID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "instance-id")
}

// GetInstanceType return instance type form metadata
func GetInstanceType(ctx context.Context) (string, error) {
	return getMetadata(ctx, "instance/instance-type")
}

// GetRegionID return region ID form metadata
func GetRegionID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "region-id")
}

// GetZoneID return zone ID from metadata
func GetZoneID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "zone-id")
}

// GetVpcID return vpc ID belong to ECS instance form metadata
func GetVpcID(ctx context.Context) (string, error) {
	return getMetadata(ctx, "vpc-id")
}

// GetCIDRBlock return ipv4 CIDR belong to ECS instance form metadata
func GetCIDRBlock(ctx context.Context) (string, error) {
	return getMetadata(ctx, "vswitch-cidr-block")
}

// GetENIGateway return eni gateway config
func GetENIGateway(ctx context.Context, mac string) (*net.IPNet, error) {
	gwStr, err := getMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/gateway", mac))
	if err != nil {
		return nil, err
	}
	maskStr, err := getMetadata(ctx, fmt.Sprintf("network/interfaces/macs/%s/netmask", mac))
	if err != nil {
		return nil, err
	}
	gw := net.ParseIP(gwStr)
	if gw == nil {
		return nil, fmt.Errorf("failed to parse ip %s", gwStr)
	}
	mask := net.ParseIP(maskStr)
	if mask == nil {
		return nil, fmt.Errorf("failed to parse ip %s", maskStr)
	}

	return &net.IPNet{
		IP:   gw,
		Mask: net.IPMask(mask),
	}, nil
}

// getMetadata get metadata
// see https://help.aliyun.com/knowledge_detail/49122.html
func getMetadata(ctx context.Context, path string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	url := fmt.Sprintf("%s/%s", metadataURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
