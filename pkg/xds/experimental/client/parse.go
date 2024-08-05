// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"

	clusterpb "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	endpointpb "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	listenerpb "github.com/cilium/proxy/go/envoy/config/listener/v3"
	routepb "github.com/cilium/proxy/go/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/envoy"
)

func parseResource(typeUrl string, res *anypb.Any) (proto.Message, string, error) {
	msg, err := res.UnmarshalNew()
	if err != nil {
		return nil, "", fmt.Errorf("resource typeUrl=%q: unmarshal: %w", typeUrl, err)
	}
	var name string
	switch typeUrl {
	case envoy.ListenerTypeURL:
		listener, ok := msg.(*listenerpb.Listener)
		if !ok {
			return nil, "", fmt.Errorf("invalid type for Listener: %T", msg)
		}
		name = listener.Name
	case envoy.ClusterTypeURL:
		cluster, ok := msg.(*clusterpb.Cluster)
		if !ok {
			return nil, "", fmt.Errorf("invalid type for Cluster: %T", msg)
		}
		name = cluster.Name
	case envoy.EndpointTypeURL:
		cla, ok := msg.(*endpointpb.ClusterLoadAssignment)
		if !ok {
			return nil, "", fmt.Errorf("invalid type for ClusterLoadAssignment: %T", msg)
		}
		name = cla.GetClusterName()
	case envoy.RouteTypeURL:
		rc, ok := msg.(*routepb.RouteConfiguration)
		if !ok {
			return nil, "", fmt.Errorf("invalid type for RouteConfiguration: %T", msg)
		}
		name = rc.GetName()
	default:
		return nil, "", fmt.Errorf("unhandled typeUrl=%q", typeUrl)
	}
	if name == "" {
		return nil, "", fmt.Errorf("missing name for typeUrl=%q", typeUrl)
	}
	return msg, name, nil
}
