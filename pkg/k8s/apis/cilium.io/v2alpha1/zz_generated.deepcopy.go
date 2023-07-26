//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package v2alpha1

import (
	flow "github.com/cilium/cilium/api/v1/flow"
	models "github.com/cilium/cilium/api/v1/models"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	api "github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumBGPFamily) DeepCopyInto(out *CiliumBGPFamily) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumBGPFamily.
func (in *CiliumBGPFamily) DeepCopy() *CiliumBGPFamily {
	if in == nil {
		return nil
	}
	out := new(CiliumBGPFamily)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumBGPNeighbor) DeepCopyInto(out *CiliumBGPNeighbor) {
	*out = *in
	if in.PeerPort != nil {
		in, out := &in.PeerPort, &out.PeerPort
		*out = new(int32)
		**out = **in
	}
	if in.EBGPMultihopTTL != nil {
		in, out := &in.EBGPMultihopTTL, &out.EBGPMultihopTTL
		*out = new(int32)
		**out = **in
	}
	if in.ConnectRetryTimeSeconds != nil {
		in, out := &in.ConnectRetryTimeSeconds, &out.ConnectRetryTimeSeconds
		*out = new(int32)
		**out = **in
	}
	if in.HoldTimeSeconds != nil {
		in, out := &in.HoldTimeSeconds, &out.HoldTimeSeconds
		*out = new(int32)
		**out = **in
	}
	if in.KeepAliveTimeSeconds != nil {
		in, out := &in.KeepAliveTimeSeconds, &out.KeepAliveTimeSeconds
		*out = new(int32)
		**out = **in
	}
	if in.GracefulRestart != nil {
		in, out := &in.GracefulRestart, &out.GracefulRestart
		*out = new(CiliumBGPNeighborGracefulRestart)
		(*in).DeepCopyInto(*out)
	}
	if in.Families != nil {
		in, out := &in.Families, &out.Families
		*out = make([]CiliumBGPFamily, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumBGPNeighbor.
func (in *CiliumBGPNeighbor) DeepCopy() *CiliumBGPNeighbor {
	if in == nil {
		return nil
	}
	out := new(CiliumBGPNeighbor)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumBGPNeighborGracefulRestart) DeepCopyInto(out *CiliumBGPNeighborGracefulRestart) {
	*out = *in
	if in.RestartTimeSeconds != nil {
		in, out := &in.RestartTimeSeconds, &out.RestartTimeSeconds
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumBGPNeighborGracefulRestart.
func (in *CiliumBGPNeighborGracefulRestart) DeepCopy() *CiliumBGPNeighborGracefulRestart {
	if in == nil {
		return nil
	}
	out := new(CiliumBGPNeighborGracefulRestart)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumBGPPeeringPolicy) DeepCopyInto(out *CiliumBGPPeeringPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumBGPPeeringPolicy.
func (in *CiliumBGPPeeringPolicy) DeepCopy() *CiliumBGPPeeringPolicy {
	if in == nil {
		return nil
	}
	out := new(CiliumBGPPeeringPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumBGPPeeringPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumBGPPeeringPolicyList) DeepCopyInto(out *CiliumBGPPeeringPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumBGPPeeringPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumBGPPeeringPolicyList.
func (in *CiliumBGPPeeringPolicyList) DeepCopy() *CiliumBGPPeeringPolicyList {
	if in == nil {
		return nil
	}
	out := new(CiliumBGPPeeringPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumBGPPeeringPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumBGPPeeringPolicySpec) DeepCopyInto(out *CiliumBGPPeeringPolicySpec) {
	*out = *in
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.VirtualRouters != nil {
		in, out := &in.VirtualRouters, &out.VirtualRouters
		*out = make([]CiliumBGPVirtualRouter, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumBGPPeeringPolicySpec.
func (in *CiliumBGPPeeringPolicySpec) DeepCopy() *CiliumBGPPeeringPolicySpec {
	if in == nil {
		return nil
	}
	out := new(CiliumBGPPeeringPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumBGPVirtualRouter) DeepCopyInto(out *CiliumBGPVirtualRouter) {
	*out = *in
	if in.ExportPodCIDR != nil {
		in, out := &in.ExportPodCIDR, &out.ExportPodCIDR
		*out = new(bool)
		**out = **in
	}
	if in.ServiceSelector != nil {
		in, out := &in.ServiceSelector, &out.ServiceSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Neighbors != nil {
		in, out := &in.Neighbors, &out.Neighbors
		*out = make([]CiliumBGPNeighbor, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumBGPVirtualRouter.
func (in *CiliumBGPVirtualRouter) DeepCopy() *CiliumBGPVirtualRouter {
	if in == nil {
		return nil
	}
	out := new(CiliumBGPVirtualRouter)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumCIDRGroup) DeepCopyInto(out *CiliumCIDRGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumCIDRGroup.
func (in *CiliumCIDRGroup) DeepCopy() *CiliumCIDRGroup {
	if in == nil {
		return nil
	}
	out := new(CiliumCIDRGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumCIDRGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumCIDRGroupList) DeepCopyInto(out *CiliumCIDRGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumCIDRGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumCIDRGroupList.
func (in *CiliumCIDRGroupList) DeepCopy() *CiliumCIDRGroupList {
	if in == nil {
		return nil
	}
	out := new(CiliumCIDRGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumCIDRGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumCIDRGroupSpec) DeepCopyInto(out *CiliumCIDRGroupSpec) {
	*out = *in
	if in.ExternalCIDRs != nil {
		in, out := &in.ExternalCIDRs, &out.ExternalCIDRs
		*out = make([]api.CIDR, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumCIDRGroupSpec.
func (in *CiliumCIDRGroupSpec) DeepCopy() *CiliumCIDRGroupSpec {
	if in == nil {
		return nil
	}
	out := new(CiliumCIDRGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEndpointSlice) DeepCopyInto(out *CiliumEndpointSlice) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Endpoints != nil {
		in, out := &in.Endpoints, &out.Endpoints
		*out = make([]CoreCiliumEndpoint, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEndpointSlice.
func (in *CiliumEndpointSlice) DeepCopy() *CiliumEndpointSlice {
	if in == nil {
		return nil
	}
	out := new(CiliumEndpointSlice)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumEndpointSlice) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEndpointSliceList) DeepCopyInto(out *CiliumEndpointSliceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumEndpointSlice, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEndpointSliceList.
func (in *CiliumEndpointSliceList) DeepCopy() *CiliumEndpointSliceList {
	if in == nil {
		return nil
	}
	out := new(CiliumEndpointSliceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumEndpointSliceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumFlowLogging) DeepCopyInto(out *CiliumFlowLogging) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumFlowLogging.
func (in *CiliumFlowLogging) DeepCopy() *CiliumFlowLogging {
	if in == nil {
		return nil
	}
	out := new(CiliumFlowLogging)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumFlowLogging) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumFlowLoggingList) DeepCopyInto(out *CiliumFlowLoggingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumFlowLogging, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumFlowLoggingList.
func (in *CiliumFlowLoggingList) DeepCopy() *CiliumFlowLoggingList {
	if in == nil {
		return nil
	}
	out := new(CiliumFlowLoggingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumFlowLoggingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumL2AnnouncementPolicy) DeepCopyInto(out *CiliumL2AnnouncementPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumL2AnnouncementPolicy.
func (in *CiliumL2AnnouncementPolicy) DeepCopy() *CiliumL2AnnouncementPolicy {
	if in == nil {
		return nil
	}
	out := new(CiliumL2AnnouncementPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumL2AnnouncementPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumL2AnnouncementPolicyList) DeepCopyInto(out *CiliumL2AnnouncementPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumL2AnnouncementPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumL2AnnouncementPolicyList.
func (in *CiliumL2AnnouncementPolicyList) DeepCopy() *CiliumL2AnnouncementPolicyList {
	if in == nil {
		return nil
	}
	out := new(CiliumL2AnnouncementPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumL2AnnouncementPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumL2AnnouncementPolicySpec) DeepCopyInto(out *CiliumL2AnnouncementPolicySpec) {
	*out = *in
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ServiceSelector != nil {
		in, out := &in.ServiceSelector, &out.ServiceSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Interfaces != nil {
		in, out := &in.Interfaces, &out.Interfaces
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumL2AnnouncementPolicySpec.
func (in *CiliumL2AnnouncementPolicySpec) DeepCopy() *CiliumL2AnnouncementPolicySpec {
	if in == nil {
		return nil
	}
	out := new(CiliumL2AnnouncementPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumL2AnnouncementPolicyStatus) DeepCopyInto(out *CiliumL2AnnouncementPolicyStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumL2AnnouncementPolicyStatus.
func (in *CiliumL2AnnouncementPolicyStatus) DeepCopy() *CiliumL2AnnouncementPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(CiliumL2AnnouncementPolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumLoadBalancerIPPool) DeepCopyInto(out *CiliumLoadBalancerIPPool) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumLoadBalancerIPPool.
func (in *CiliumLoadBalancerIPPool) DeepCopy() *CiliumLoadBalancerIPPool {
	if in == nil {
		return nil
	}
	out := new(CiliumLoadBalancerIPPool)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumLoadBalancerIPPool) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumLoadBalancerIPPoolCIDRBlock) DeepCopyInto(out *CiliumLoadBalancerIPPoolCIDRBlock) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumLoadBalancerIPPoolCIDRBlock.
func (in *CiliumLoadBalancerIPPoolCIDRBlock) DeepCopy() *CiliumLoadBalancerIPPoolCIDRBlock {
	if in == nil {
		return nil
	}
	out := new(CiliumLoadBalancerIPPoolCIDRBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumLoadBalancerIPPoolList) DeepCopyInto(out *CiliumLoadBalancerIPPoolList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumLoadBalancerIPPool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumLoadBalancerIPPoolList.
func (in *CiliumLoadBalancerIPPoolList) DeepCopy() *CiliumLoadBalancerIPPoolList {
	if in == nil {
		return nil
	}
	out := new(CiliumLoadBalancerIPPoolList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumLoadBalancerIPPoolList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumLoadBalancerIPPoolSpec) DeepCopyInto(out *CiliumLoadBalancerIPPoolSpec) {
	*out = *in
	if in.ServiceSelector != nil {
		in, out := &in.ServiceSelector, &out.ServiceSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Cidrs != nil {
		in, out := &in.Cidrs, &out.Cidrs
		*out = make([]CiliumLoadBalancerIPPoolCIDRBlock, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumLoadBalancerIPPoolSpec.
func (in *CiliumLoadBalancerIPPoolSpec) DeepCopy() *CiliumLoadBalancerIPPoolSpec {
	if in == nil {
		return nil
	}
	out := new(CiliumLoadBalancerIPPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumLoadBalancerIPPoolStatus) DeepCopyInto(out *CiliumLoadBalancerIPPoolStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumLoadBalancerIPPoolStatus.
func (in *CiliumLoadBalancerIPPoolStatus) DeepCopy() *CiliumLoadBalancerIPPoolStatus {
	if in == nil {
		return nil
	}
	out := new(CiliumLoadBalancerIPPoolStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumNodeConfig) DeepCopyInto(out *CiliumNodeConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumNodeConfig.
func (in *CiliumNodeConfig) DeepCopy() *CiliumNodeConfig {
	if in == nil {
		return nil
	}
	out := new(CiliumNodeConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumNodeConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumNodeConfigList) DeepCopyInto(out *CiliumNodeConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumNodeConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumNodeConfigList.
func (in *CiliumNodeConfigList) DeepCopy() *CiliumNodeConfigList {
	if in == nil {
		return nil
	}
	out := new(CiliumNodeConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumNodeConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumNodeConfigSpec) DeepCopyInto(out *CiliumNodeConfigSpec) {
	*out = *in
	if in.Defaults != nil {
		in, out := &in.Defaults, &out.Defaults
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumNodeConfigSpec.
func (in *CiliumNodeConfigSpec) DeepCopy() *CiliumNodeConfigSpec {
	if in == nil {
		return nil
	}
	out := new(CiliumNodeConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumPodIPPool) DeepCopyInto(out *CiliumPodIPPool) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumPodIPPool.
func (in *CiliumPodIPPool) DeepCopy() *CiliumPodIPPool {
	if in == nil {
		return nil
	}
	out := new(CiliumPodIPPool)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumPodIPPool) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumPodIPPoolList) DeepCopyInto(out *CiliumPodIPPoolList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumPodIPPool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumPodIPPoolList.
func (in *CiliumPodIPPoolList) DeepCopy() *CiliumPodIPPoolList {
	if in == nil {
		return nil
	}
	out := new(CiliumPodIPPoolList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumPodIPPoolList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CoreCiliumEndpoint) DeepCopyInto(out *CoreCiliumEndpoint) {
	*out = *in
	if in.Networking != nil {
		in, out := &in.Networking, &out.Networking
		*out = new(v2.EndpointNetworking)
		(*in).DeepCopyInto(*out)
	}
	out.Encryption = in.Encryption
	if in.NamedPorts != nil {
		in, out := &in.NamedPorts, &out.NamedPorts
		*out = make(models.NamedPorts, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(models.Port)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CoreCiliumEndpoint.
func (in *CoreCiliumEndpoint) DeepCopy() *CoreCiliumEndpoint {
	if in == nil {
		return nil
	}
	out := new(CoreCiliumEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EgressRule) DeepCopyInto(out *EgressRule) {
	*out = *in
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.PodSelector != nil {
		in, out := &in.PodSelector, &out.PodSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EgressRule.
func (in *EgressRule) DeepCopy() *EgressRule {
	if in == nil {
		return nil
	}
	out := new(EgressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FlowLoggingSpec) DeepCopyInto(out *FlowLoggingSpec) {
	*out = *in
	if in.FieldMask != nil {
		in, out := &in.FieldMask, &out.FieldMask
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AllowList != nil {
		in, out := &in.AllowList, &out.AllowList
		*out = make([]*flow.FlowFilter, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = (*in).DeepCopy()
			}
		}
	}
	if in.DenyList != nil {
		in, out := &in.DenyList, &out.DenyList
		*out = make([]*flow.FlowFilter, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = (*in).DeepCopy()
			}
		}
	}
	if in.Expiration != nil {
		in, out := &in.Expiration, &out.Expiration
		*out = (*in).DeepCopy()
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FlowLoggingSpec.
func (in *FlowLoggingSpec) DeepCopy() *FlowLoggingSpec {
	if in == nil {
		return nil
	}
	out := new(FlowLoggingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FlowLoggingStatus) DeepCopyInto(out *FlowLoggingStatus) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FlowLoggingStatus.
func (in *FlowLoggingStatus) DeepCopy() *FlowLoggingStatus {
	if in == nil {
		return nil
	}
	out := new(FlowLoggingStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPPoolSpec) DeepCopyInto(out *IPPoolSpec) {
	*out = *in
	if in.IPv4 != nil {
		in, out := &in.IPv4, &out.IPv4
		*out = new(IPv4PoolSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.IPv6 != nil {
		in, out := &in.IPv6, &out.IPv6
		*out = new(IPv6PoolSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPPoolSpec.
func (in *IPPoolSpec) DeepCopy() *IPPoolSpec {
	if in == nil {
		return nil
	}
	out := new(IPPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPv4PoolSpec) DeepCopyInto(out *IPv4PoolSpec) {
	*out = *in
	if in.CIDRs != nil {
		in, out := &in.CIDRs, &out.CIDRs
		*out = make([]PoolCIDR, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPv4PoolSpec.
func (in *IPv4PoolSpec) DeepCopy() *IPv4PoolSpec {
	if in == nil {
		return nil
	}
	out := new(IPv4PoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPv6PoolSpec) DeepCopyInto(out *IPv6PoolSpec) {
	*out = *in
	if in.CIDRs != nil {
		in, out := &in.CIDRs, &out.CIDRs
		*out = make([]PoolCIDR, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPv6PoolSpec.
func (in *IPv6PoolSpec) DeepCopy() *IPv6PoolSpec {
	if in == nil {
		return nil
	}
	out := new(IPv6PoolSpec)
	in.DeepCopyInto(out)
	return out
}
