// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	discoverypb "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/sets"
)

type RequestCons interface {
	*discoverypb.DiscoveryRequest | *discoverypb.DeltaDiscoveryRequest
}

type ResponseCons interface {
	*discoverypb.DiscoveryResponse | *discoverypb.DeltaDiscoveryResponse
	GetTypeUrl() string
}

// nameToResource maps a resource name to a proto representation of the resource.
type nameToResource map[string]proto.Message

type Helper[ReqT RequestCons, RespT ResponseCons] interface {
	getTransport(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) (transport[ReqT, RespT], error)
	resp2ack(RespT, []string) ReqT
	initialReq(typeUrl string) ReqT
	prepareObsReq(obsReq *observeRequest, curr []string) (ReqT, error)
	resp2resources(RespT) (nameToResource, error)
	resp2nack(resp RespT, detail error) ReqT
	resp2deleted(RespT) []string
}

type sotwHelper struct {
	node *corepb.Node
}

var _ Helper[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse] = (*sotwHelper)(nil)
var _ Helper[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse] = (*deltaHelper)(nil)

func (sotw *sotwHelper) getTransport(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) (transport[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse], error) {
	return client.StreamAggregatedResources(ctx, grpc.WaitForReady(true))
}

func (sotw *sotwHelper) resp2ack(resp *discoverypb.DiscoveryResponse, resourceNames []string) *discoverypb.DiscoveryRequest {
	return &discoverypb.DiscoveryRequest{
		Node:          sotw.node,
		VersionInfo:   resp.GetVersionInfo(),
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ResourceNames: resourceNames,
	}
}

func (sotw *sotwHelper) initialReq(typeUrl string) *discoverypb.DiscoveryRequest {
	return &discoverypb.DiscoveryRequest{
		Node:    sotw.node,
		TypeUrl: typeUrl,
	}
}

func (sotw *sotwHelper) prepareObsReq(obsReq *observeRequest, curr []string) (*discoverypb.DiscoveryRequest, error) {
	reqResourceNames := sets.Set[string]{}
	reqResourceNames.Insert(curr...)
	reqResourceNames.Insert(obsReq.resourceNames...)

	return &discoverypb.DiscoveryRequest{
		Node:          sotw.node,
		TypeUrl:       obsReq.typeUrl,
		ResourceNames: slices.Collect(maps.Keys(reqResourceNames)),
	}, nil
}

func (sotw *sotwHelper) resp2resources(resp *discoverypb.DiscoveryResponse) (nameToResource, error) {
	var errs error
	upsertedResources := make(nameToResource)
	for _, res := range resp.GetResources() {
		typeUrl := res.GetTypeUrl()
		if typeUrl != resp.GetTypeUrl() {
			return nil, fmt.Errorf("mismatched typeUrls, got = %s, want = %s", typeUrl, resp.GetTypeUrl())
		}
		msg, name, err := parseResource(typeUrl, res)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		upsertedResources[name] = msg
	}
	return upsertedResources, errs
}

func (sotw *sotwHelper) resp2nack(resp *discoverypb.DiscoveryResponse, detail error) *discoverypb.DiscoveryRequest {
	return &discoverypb.DiscoveryRequest{
		Node:          sotw.node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ErrorDetail: &statuspb.Status{
			Code:    int32(codes.Unknown),
			Message: detail.Error(),
		},
	}
}

func (sotw *sotwHelper) resp2deleted(resp *discoverypb.DiscoveryResponse) []string {
	return nil
}

type deltaHelper struct {
	node *corepb.Node
}

func (delta *deltaHelper) getTransport(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) (transport[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse], error) {
	return client.DeltaAggregatedResources(ctx, grpc.WaitForReady(true))
}

func (delta *deltaHelper) initialReq(typeUrl string) *discoverypb.DeltaDiscoveryRequest {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:    delta.node,
		TypeUrl: typeUrl,
	}
}

func (delta *deltaHelper) prepareObsReq(obsReq *observeRequest, _ []string) (*discoverypb.DeltaDiscoveryRequest, error) {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:                   delta.node,
		TypeUrl:                obsReq.typeUrl,
		ResourceNamesSubscribe: obsReq.resourceNames,
	}, nil
}

func (delta *deltaHelper) resp2resources(resp *discoverypb.DeltaDiscoveryResponse) (nameToResource, error) {
	var errs error
	ret := make(nameToResource, len(resp.GetResources()))
	for _, res := range resp.GetResources() {
		name := res.GetName()
		msg, _, err := parseResource(resp.GetTypeUrl(), res.GetResource())
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		ret[name] = msg
	}
	return ret, errs
}

func (delta *deltaHelper) resp2ack(resp *discoverypb.DeltaDiscoveryResponse, _ []string) *discoverypb.DeltaDiscoveryRequest {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:          delta.node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
	}
}

func (delta *deltaHelper) resp2nack(resp *discoverypb.DeltaDiscoveryResponse, detail error) *discoverypb.DeltaDiscoveryRequest {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:          delta.node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ErrorDetail: &statuspb.Status{
			Code:    int32(codes.Unknown),
			Message: detail.Error(),
		},
	}
}

func (delta *deltaHelper) resp2deleted(resp *discoverypb.DeltaDiscoveryResponse) []string {
	return resp.GetRemovedResources()
}
