// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import discoverypb "github.com/cilium/proxy/go/envoy/service/discovery/v3"

type transport[req RequestCons, resp ResponseCons] interface {
	Send(req) error
	Recv() (resp, error)
}

var _ transport[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse] = (discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient)(nil)
var _ transport[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse] = (discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient)(nil)
