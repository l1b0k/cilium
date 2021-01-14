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

package eni

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/alibabacloud/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
	"github.com/sirupsen/logrus"
)

// The following error constants represent the error conditions for
// CreateInterface without additional context embedded in order to make them
// usable for metrics accounting purposes.
const (
	errUnableToDetermineLimits    = "unable to determine limits"
	errUnableToGetSecurityGroups  = "unable to get security groups"
	errUnableToCreateENI          = "unable to create ENI"
	errUnableToAttachENI          = "unable to attach ENI"
	errUnableToMarkENIForDeletion = "unable to mark ENI for deletion"
	errUnableToFindSubnet         = "unable to find matching subnet"
)

type Node struct {
	// node contains the general purpose fields of a node
	node *ipam.Node

	// mutex protects members below this field
	mutex lock.RWMutex

	// enis is the list of ENIs attached to the node indexed by ENI ID.
	// Protected by Node.mutex.
	enis map[string]eniTypes.ENI

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the ecs node manager responsible for this node
	manager *InstancesManager
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with ENI specific information
func (n *Node) PopulateStatusFields(resource *v2.CiliumNode) {
	resource.Status.AlibabaCloud.ENIs = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok {
				resource.Status.AlibabaCloud.ENIs[interfaceID] = *e.DeepCopy()
			}
			return nil
		})

	return
}

// CreateInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry) (
	int, string, error) {
	l, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return 0, errUnableToDetermineLimits, fmt.Errorf(errUnableToDetermineLimits)
	}

	n.mutex.RLock()
	resource := *n.k8sObj
	n.mutex.RUnlock()

	// Must allocate secondary ENI IPs as needed, up to ENI instance limit - 1 (reserve 1 for primary IP)
	toAllocate := math.IntMin(allocation.MaxIPsToAllocate, l.IPv4-1)
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	bestSubnet := n.manager.FindOneVSwitch(resource.Spec.AlibabaCloud.VpcID, resource.Spec.AlibabaCloud.AvailabilityZone,
		toAllocate, resource.Spec.AlibabaCloud.VSwitchTags)
	if bestSubnet == nil {
		return 0,
			errUnableToFindSubnet,
			fmt.Errorf(
				"no matching vSwitch available for interface creation (VPC=%s AZ=%s SubnetTags=%s",
				resource.Spec.AlibabaCloud.VpcID,
				resource.Spec.AlibabaCloud.AvailabilityZone,
				resource.Spec.AlibabaCloud.VSwitchTags,
			)
	}

	securityGroupIDs, err := n.getSecurityGroupIDs(ctx, resource.Spec.AlibabaCloud)
	if err != nil {
		return 0,
			errUnableToGetSecurityGroups,
			fmt.Errorf("%s %s", errUnableToGetSecurityGroups, err)
	}

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"securityGroupIDs": securityGroupIDs,
		"vSwitchID":        bestSubnet.ID,
		"toAllocate":       toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")

	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, toAllocate, bestSubnet.ID, securityGroupIDs)
	if err != nil {
		return 0, errUnableToCreateENI, fmt.Errorf("%s %s", errUnableToCreateENI, err)
	}

	scopedLog = scopedLog.WithField(fieldEniID, eniID)
	scopedLog.Info("Created new ENI")

	err = n.manager.api.AttachNetworkInterface(ctx, n.node.InstanceID(), eniID)
	if err != nil {
		return 0, errUnableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}
	_, err = n.manager.api.WaitEniAttached(ctx, eniID)
	if err != nil {
		return 0, errUnableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}

	scopedLog.Info("Attached ENI to instance")

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(n.node.InstanceID(), eni)
	return toAllocate, "", nil

}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the AlibabaCloud API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (ipamTypes.AllocationMap, error) {
	instanceID := n.node.InstanceID()
	available := ipamTypes.AllocationMap{}

	n.mutex.Lock()
	n.enis = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(instanceID,
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if !ok {
				return nil
			}

			n.enis[e.NetworkInterfaceID] = *e
			if len(e.PrivateIPSets) <= 1 {
				return nil
			}

			for _, ip := range e.PrivateIPSets {
				if ip.Primary {
					continue
				}
				available[ip.PrivateIpAddress] = ipamTypes.AllocationIP{Resource: e.NetworkInterfaceID}
			}
			return nil
		})
	enis := len(n.enis)
	n.mutex.Unlock()

	// An ECS instance has at least one ENI attached, no ENI found implies instance not found.
	if enis == 0 {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, fmt.Errorf("unable to retrieve ENIs")
	}

	return available, nil
}

// PrepareIPAllocation returns the number of ENI IPs and interfaces that can be
// allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry) (*ipam.AllocationAction, error) {
	l, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, fmt.Errorf("Unable to determine limits")
	}
	a := &ipam.AllocationAction{}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:  e.NetworkInterfaceID,
			"ipv4Limit": l.IPv4,
			"allocated": len(e.PrivateIPSets),
		}).Debug("Considering ENI for allocation")

		availableOnENI := math.IntMax(l.IPv4-len(e.PrivateIPSets), 0)
		if availableOnENI <= 0 {
			continue
		} else {
			a.AvailableInterfaces++
		}

		scopedLog.WithFields(logrus.Fields{
			fieldEniID:       e.NetworkInterfaceID,
			"availableOnEni": availableOnENI,
		}).Debug("ENI has IPs available")

		if subnet := n.manager.GetVSwitch(e.VSwitch.VSwitchID); subnet != nil {
			if subnet.AvailableAddresses > 0 && a.InterfaceID == "" {
				scopedLog.WithFields(logrus.Fields{
					"vSwitchID":          e.VSwitch.VSwitchID,
					"availableAddresses": subnet.AvailableAddresses,
				}).Debug("Subnet has IPs available")

				a.InterfaceID = key
				a.PoolID = ipamTypes.PoolID(subnet.ID)
				a.AvailableForAllocation = math.IntMin(subnet.AvailableAddresses, availableOnENI)
			}
		}
	}
	a.AvailableInterfaces = l.Adapters - len(n.enis) + a.AvailableInterfaces
	return a, nil
}

// AllocateIPs performs the ENI allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction) error {
	_, err := n.manager.api.AssignPrivateIpAddresses(ctx, a.InterfaceID, a.AvailableForAllocation)
	return err
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for key, e := range n.enis {
		scopedLog.WithFields(logrus.Fields{
			fieldEniID:     e.NetworkInterfaceID,
			"numAddresses": len(e.PrivateIPSets),
		}).Debug("Considering ENI for IP release")

		// Count free IP addresses on this ENI
		ipsOnENI := n.k8sObj.Status.AlibabaCloud.ENIs[e.NetworkInterfaceID].PrivateIPSets
		freeIpsOnENI := []string{}
		for _, ip := range ipsOnENI {
			// exclude primary IPs
			if ip.Primary {
				continue
			}
			_, ipUsed := n.k8sObj.Status.IPAM.Used[ip.PrivateIpAddress]
			if !ipUsed {
				freeIpsOnENI = append(freeIpsOnENI, ip.PrivateIpAddress)
			}
		}
		freeOnENICount := len(freeIpsOnENI)

		if freeOnENICount <= 0 {
			continue
		}

		scopedLog.WithFields(logrus.Fields{
			fieldEniID:       e.NetworkInterfaceID,
			"excessIPs":      excessIPs,
			"freeOnENICount": freeOnENICount,
		}).Debug("ENI has unused IPs that can be released")
		maxReleaseOnENI := math.IntMin(freeOnENICount, excessIPs)

		r.InterfaceID = key
		r.PoolID = ipamTypes.PoolID(e.Vpc.VpcID)
		r.IPsToRelease = freeIpsOnENI[:maxReleaseOnENI]
	}

	return r
}

// ReleaseIPs performs the ENI IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction) error {
	return n.manager.api.UnassignPrivateIpAddresses(ctx, r.InterfaceID, r.IPsToRelease)
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Retrieve l for the instance type
	l, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		return 0
	}
	// TODO reserve Primary ENI
	// Return the maximum amount of IP addresses allocatable on the instance
	// reserve Primary eni 's Primary IP
	return l.Adapters*l.IPv4 - 1
}

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil || n.node == nil {
		return log
	}

	return log.WithField("instanceID", n.node.InstanceID())
}

// getLimits returns the interface and IP limits of this node
func (n *Node) getLimits() (ipamTypes.Limits, bool) {
	n.mutex.RLock()
	l, b := n.getLimitsLocked()
	n.mutex.RUnlock()
	return l, b
}

// getLimitsLocked is the same function as getLimits, but assumes the n.mutex
// is read locked.
func (n *Node) getLimitsLocked() (ipamTypes.Limits, bool) {
	return limits.Get(n.k8sObj.Spec.AlibabaCloud.InstanceType)
}

func (n *Node) getSecurityGroupIDs(ctx context.Context, eniSpec eniTypes.AlibabaCloudSpec) ([]string, error) {
	// 1. use security group defined by user
	// 2. use security group used by eth0

	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	if len(eniSpec.SecurityGroupTags) > 0 {
		securityGroups := n.manager.FindSecurityGroupByTags(eniSpec.VpcID, eniSpec.SecurityGroupTags)
		if len(securityGroups) == 0 {
			n.loggerLocked().WithFields(logrus.Fields{
				"vpcID": eniSpec.VpcID,
				"tags":  eniSpec.SecurityGroupTags,
			}).Warn("No security groups match required vpc id and tags, using eth0 security groups")
		} else {
			groups := make([]string, 0, len(securityGroups))
			for _, secGroup := range securityGroups {
				groups = append(groups, secGroup.ID)
			}
			return groups, nil
		}
	}

	var securityGroups []string

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok && e.Type == "Primary" {
				securityGroups = make([]string, len(e.SecurityGroupIDs))
				copy(securityGroups, e.SecurityGroupIDs)
			}
			return nil
		})

	if len(securityGroups) <= 0 {
		return nil, fmt.Errorf("failed to get security group ids")
	}

	return securityGroups, nil
}
