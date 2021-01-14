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

package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"
	"k8s.io/apimachinery/pkg/util/wait"

	httperr "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
)

const (
	VpcID = "VpcId"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "alibaba-cloud-api")

var maxAttachRetries = wait.Backoff{
	Duration: 4 * time.Second,
	Factor:   1,
	Jitter:   0.1,
	Steps:    4,
	Cap:      0,
}

// Client an AlibabaCloud API client
type Client struct {
	client     *ecs.Client
	limiter    *helpers.ApiLimiter
	metricsAPI MetricsAPI
	filters    map[string]string
}

// MetricsAPI represents the metrics maintained by the AWS API client
type MetricsAPI interface {
	helpers.MetricsAPI
	ObserveAPICall(call, status string, duration float64)
}

// NewClient
func NewClient(client *ecs.Client, metrics MetricsAPI, rateLimit float64, burst int, filters map[string]string) *Client {
	return &Client{
		client:     client,
		limiter:    helpers.NewApiLimiter(metrics, rateLimit, burst),
		metricsAPI: metrics,
		filters:    filters,
	}
}

// GetInstances returns the list of all instances including their ENIs as
// instanceMap
func (c *Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	networkInterfaceSets, err := c.describeNetworkInterfaces(ctx, subnets)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaceSets {
		id, eni, err := parseENI(&iface, vpcs, subnets)
		if err != nil {
			return nil, err
		}

		instances.Update(id, ipamTypes.InterfaceRevision{
			Resource: eni,
		})
	}
	return instances, nil
}

// GetVSwitches returns all ecs subnets as a subnetMap
func (c *Client) GetVSwitches(ctx context.Context) (ipamTypes.SubnetMap, error) {
	var result ipamTypes.SubnetMap
	for i := 1; ; {
		req := ecs.CreateDescribeVSwitchesRequest()
		req.PageNumber = requests.NewInteger(i)
		req.PageSize = requests.NewInteger(50)
		req.VpcId = c.filters[VpcID]
		resp, err := c.client.DescribeVSwitches(req)
		if err != nil {
			return nil, err
		}
		if len(resp.VSwitches.VSwitch) == 0 {
			break
		}
		if result == nil {
			result = make(ipamTypes.SubnetMap, resp.TotalCount)
		}

		for _, v := range resp.VSwitches.VSwitch {
			_, ipnet, err := net.ParseCIDR(v.CidrBlock)
			if err != nil {
				return nil, err
			}
			result[v.VSwitchId] = &ipamTypes.Subnet{
				ID:                 v.VSwitchId,
				Name:               v.VSwitchName,
				CIDR:               cidr.NewCIDR(ipnet),
				AvailabilityZone:   v.ZoneId,
				VirtualNetworkID:   v.VpcId,
				AvailableAddresses: int(v.AvailableIpAddressCount),
			}
		}
		if resp.TotalCount < resp.PageNumber*resp.PageSize {
			break
		}
		i++
	}
	return result, nil
}

// GetVpc get vpc by id
func (c *Client) GetVpc(ctx context.Context, vpcID string) (*ipamTypes.VirtualNetwork, error) {
	req := ecs.CreateDescribeVpcsRequest()
	req.VpcId = vpcID
	resp, err := c.client.DescribeVpcs(req)
	if err != nil {
		return nil, err
	}
	if len(resp.Vpcs.Vpc) == 0 {
		return nil, fmt.Errorf("can't found vpc by id %s", vpcID)
	}

	return &ipamTypes.VirtualNetwork{
		ID:          resp.Vpcs.Vpc[0].VpcId,
		PrimaryCIDR: resp.Vpcs.Vpc[0].CidrBlock,
	}, nil
}

// GetVpcs retrieves and returns all Vpcs
func (c *Client) GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	var result ipamTypes.VirtualNetworkMap
	for i := 1; ; {
		req := ecs.CreateDescribeVpcsRequest()
		req.PageNumber = requests.NewInteger(i)
		req.PageSize = requests.NewInteger(50)
		resp, err := c.client.DescribeVpcs(req)
		if err != nil {
			return nil, err
		}
		if len(resp.Vpcs.Vpc) == 0 {
			break
		}
		if result == nil {
			result = make(ipamTypes.VirtualNetworkMap, resp.TotalCount)
		}
		for _, v := range resp.Vpcs.Vpc {
			result[v.VpcId] = &ipamTypes.VirtualNetwork{
				ID:          v.VpcId,
				PrimaryCIDR: v.CidrBlock,
			}
		}
		if resp.TotalCount < resp.PageNumber*resp.PageSize {
			break
		}
		i++
	}
	return result, nil
}

// GetInstanceTypes returns all the known ECS instance types in the configured region
func (c *Client) GetInstanceTypes(ctx context.Context) ([]ecs.InstanceType, error) {
	req := ecs.CreateDescribeInstanceTypesRequest()
	resp, err := c.client.DescribeInstanceTypes(req)
	if err != nil {
		return nil, err
	}

	return resp.InstanceTypes.InstanceType, nil
}

// GetSecurityGroups return all sg
func (c *Client) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	var result types.SecurityGroupMap
	for i := 1; ; {
		req := ecs.CreateDescribeSecurityGroupsRequest()
		req.PageNumber = requests.NewInteger(i)
		req.PageSize = requests.NewInteger(50)
		resp, err := c.client.DescribeSecurityGroups(req)
		if err != nil {
			return nil, err
		}
		if len(resp.SecurityGroups.SecurityGroup) == 0 {
			break
		}
		if result == nil {
			result = make(types.SecurityGroupMap, resp.TotalCount)
		}
		for _, v := range resp.SecurityGroups.SecurityGroup {
			result[v.VpcId] = &types.SecurityGroup{
				ID:    v.SecurityGroupId,
				VpcID: v.VpcId,
				Tags:  parseEcsTags(v.Tags.Tag),
			}
		}
		if resp.TotalCount < resp.PageNumber*resp.PageSize {
			break
		}
		i++
	}
	return result, nil
}

// DescribeNetworkInterface get ENI by id
func (c *Client) DescribeNetworkInterface(ctx context.Context, eniID string) (*ecs.NetworkInterfaceSet, error) {
	req := ecs.CreateDescribeNetworkInterfacesRequest()
	req.NetworkInterfaceId = &[]string{eniID}
	resp, err := c.client.DescribeNetworkInterfaces(req)
	if err != nil {
		return nil, err
	}
	if len(resp.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
		return nil, fmt.Errorf("failed to find eni %s", eniID)
	}
	return &resp.NetworkInterfaceSets.NetworkInterfaceSet[0], nil
}

// CreateNetworkInterface creates an ENI with the given parameters
func (c *Client) CreateNetworkInterface(ctx context.Context, toAllocate int, vSwitchID string, groups []string) (string, *eniTypes.ENI, error) {
	req := ecs.CreateCreateNetworkInterfaceRequest()
	req.SecondaryPrivateIpAddressCount = requests.NewInteger(toAllocate)
	req.VSwitchId = vSwitchID
	req.SecurityGroupIds = &groups
	c.limiter.Limit(ctx, "CreateNetworkInterface")
	sinceStart := spanstat.Start()
	resp, err := c.client.CreateNetworkInterface(req)
	c.metricsAPI.ObserveAPICall("CreateNetworkInterface", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return "", nil, err
	}

	var privateIPSets []eniTypes.PrivateIPSet
	for _, p := range resp.PrivateIpSets.PrivateIpSet {
		privateIPSets = append(privateIPSets, eniTypes.PrivateIPSet{
			Primary:          p.Primary,
			PrivateIpAddress: p.PrivateIpAddress,
		})
	}
	eni := &eniTypes.ENI{
		NetworkInterfaceID:   resp.NetworkInterfaceId,
		NetworkInterfaceName: resp.NetworkInterfaceName,
		MacAddress:           resp.MacAddress,
		Type:                 resp.Type,
		SecurityGroupIDs:     resp.SecurityGroupIds.SecurityGroupId,
		Status:               resp.Status,
		Vpc: eniTypes.VPC{
			VpcID: resp.VpcId,
		},
		ZoneID: resp.ZoneId,
		VSwitch: eniTypes.VSwitch{
			VSwitchID: resp.VSwitchId,
		},
		PrimaryIPAddress: resp.PrivateIpAddress,
		PrivateIPSets:    privateIPSets,
	}
	return resp.NetworkInterfaceId, eni, nil
}

// AttachNetworkInterface attaches a previously created ENI to an instance
func (c *Client) AttachNetworkInterface(ctx context.Context, instanceID, eniID string) error {
	req := ecs.CreateAttachNetworkInterfaceRequest()
	req.InstanceId = instanceID
	req.NetworkInterfaceId = eniID
	c.limiter.Limit(ctx, "AttachNetworkInterface")
	sinceStart := spanstat.Start()
	_, err := c.client.AttachNetworkInterface(req)
	c.metricsAPI.ObserveAPICall("AttachNetworkInterface", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return err
	}
	return nil
}

// WaitEniAttached check eni is attached to ECS and return attached ECS instanceID
func (c *Client) WaitEniAttached(ctx context.Context, eniID string) (string, error) {
	instanceID := ""
	err := wait.ExponentialBackoffWithContext(ctx, maxAttachRetries, func() (done bool, err error) {
		eni, err := c.DescribeNetworkInterface(ctx, eniID)
		if err != nil {
			return false, err
		}
		if eni.Status == "InUse" {
			instanceID = eni.InstanceId
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return "", err
	}
	return instanceID, nil
}

// DeleteNetworkInterface deletes an ENI with the specified ID
func (c *Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	req := ecs.CreateDeleteNetworkInterfaceRequest()
	req.NetworkInterfaceId = eniID
	_, err := c.client.DeleteNetworkInterface(req)
	if err != nil {
		return err
	}
	// TODO: should wait eni deleted?
	return nil
}

// ModifyNetworkInterface modifies the attributes of an ENI
func (c *Client) ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error {
	return nil
}

// AssignPrivateIpAddresses assigns the specified number of secondary IP
// return allocated IPs
func (c *Client) AssignPrivateIpAddresses(ctx context.Context, eniID string, toAllocate int) ([]string, error) {
	req := ecs.CreateAssignPrivateIpAddressesRequest()
	req.NetworkInterfaceId = eniID
	req.SecondaryPrivateIpAddressCount = requests.NewInteger(toAllocate)
	resp, err := c.client.AssignPrivateIpAddresses(req)
	if err != nil {
		return nil, err
	}
	return resp.AssignedPrivateIpAddressesSet.PrivateIpSet.PrivateIpAddress, nil
}

// UnassignPrivateIpAddresses unassign specified IP addresses from ENI
// should not provide Primary IP
func (c *Client) UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error {
	req := ecs.CreateUnassignPrivateIpAddressesRequest()
	req.NetworkInterfaceId = eniID
	req.PrivateIpAddress = &addresses
	_, err := c.client.UnassignPrivateIpAddresses(req)
	return err
}

func (c *Client) describeNetworkInterfaces(ctx context.Context, subnets ipamTypes.SubnetMap) ([]ecs.NetworkInterfaceSet, error) {
	var result []ecs.NetworkInterfaceSet

	for _, subnet := range subnets {
		for i := 1; ; {
			req := ecs.CreateDescribeNetworkInterfacesRequest()
			req.PageNumber = requests.NewInteger(i)
			req.PageSize = requests.NewInteger(50)
			req.VSwitchId = subnet.ID
			resp, err := c.client.DescribeNetworkInterfaces(req)
			if err != nil {
				return nil, err
			}
			if len(resp.NetworkInterfaceSets.NetworkInterfaceSet) == 0 {
				break
			}

			for _, v := range resp.NetworkInterfaceSets.NetworkInterfaceSet {
				result = append(result, v)
			}
			if resp.TotalCount < resp.PageNumber*resp.PageSize {
				break
			}
			i++
		}
	}

	return result, nil
}

// deriveStatus returns a status string based on the HTTP response provided by
// the AlibabaCloud API server. If no specific status is provided, either "OK" or
// "Failed" is returned based on the error variable.
func deriveStatus(err error) string {
	var respErr httperr.Error
	if errors.As(err, &respErr) {
		return respErr.ErrorCode()
	}

	if err != nil {
		return "Failed"
	}

	return "OK"
}

// parseENI parses a ecs.NetworkInterface as returned by the ecs service API,
// converts it into a eniTypes.ENI object
func parseENI(iface *ecs.NetworkInterfaceSet, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (instanceID string, eni *eniTypes.ENI, err error) {
	var privateIPSets []eniTypes.PrivateIPSet
	for _, p := range iface.PrivateIpSets.PrivateIpSet {
		privateIPSets = append(privateIPSets, eniTypes.PrivateIPSet{
			Primary:          p.Primary,
			PrivateIpAddress: p.PrivateIpAddress,
		})
	}

	eni = &eniTypes.ENI{
		NetworkInterfaceID:   iface.NetworkInterfaceId,
		NetworkInterfaceName: iface.NetworkInterfaceName,
		MacAddress:           iface.MacAddress,
		Type:                 iface.Type,
		InstanceID:           iface.InstanceId,
		SecurityGroupIDs:     iface.SecurityGroupIds.SecurityGroupId,
		Status:               iface.Status,
		Vpc: eniTypes.VPC{
			VpcID: iface.VpcId,
		},
		ZoneID: iface.ZoneId,
		VSwitch: eniTypes.VSwitch{
			VSwitchID: iface.VSwitchId,
		},
		PrimaryIPAddress: iface.PrivateIpAddress,
		PrivateIPSets:    privateIPSets,
	}
	vpc, ok := vpcs[iface.VpcId]
	if ok {
		eni.Vpc.CidrBlock = vpc.PrimaryCIDR
	}

	subnet, ok := subnets[iface.VSwitchId]
	if ok && subnet.CIDR != nil {
		eni.VSwitch.CidrBlock = subnet.CIDR.String()
	}

	return iface.InstanceId, eni, nil
}

// parseEcsTags convert ECS Tags to ipam Tags
func parseEcsTags(tags []ecs.Tag) ipamTypes.Tags {
	result := make(ipamTypes.Tags, len(tags))
	for _, tag := range tags {
		result[tag.TagKey] = tag.TagValue
	}
	return result
}
