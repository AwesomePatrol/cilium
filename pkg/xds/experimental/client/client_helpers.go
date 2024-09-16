// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	discoverypb "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type RequestCons interface {
	*discoverypb.DiscoveryRequest | *discoverypb.DeltaDiscoveryRequest
}

type ResponseCons interface {
	*discoverypb.DiscoveryResponse | *discoverypb.DeltaDiscoveryResponse
	GetTypeUrl() string
}

type Helper[ReqT RequestCons, RespT ResponseCons] interface {
	getTransport(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) (transport[ReqT, RespT], error)
	resp2ack(RespT, []string) ReqT
	initialReq(typeUrl string) ReqT
	prepareObsReq(obsReq *observeRequest) (ReqT, error)
	resp2resources(RespT) (nameToResource, error)
	resp2nack(resp RespT, detail error) ReqT
}

type sotwHelper struct {
	node *corepb.Node
}

var _ Helper[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse] = (*sotwHelper)(nil)

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

func (sotw *sotwHelper) prepareObsReq(obsReq *observeRequest) (*discoverypb.DiscoveryRequest, error) {
	// TODO
	/*
		curr, err := c.getAllResources(obsReq.typeUrl)
		if err != nil {
			return nil, fmt.Errorf("get resources: %w", err)
		}
		reqResourceNames := sets.Set[string]{}
		reqResourceNames.Insert(curr.ResourceNames...)
		reqResourceNames.Insert(obsReq.resourceNames...)
	*/

	return &discoverypb.DiscoveryRequest{
		Node:    sotw.node,
		TypeUrl: obsReq.typeUrl,
		//ResourceNames: slices.Collect(maps.Keys(reqResourceNames)),
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

type deltaHelper struct {
	node *corepb.Node
}

func (delta *deltaHelper) initialReq(typeUrl string) *discoverypb.DeltaDiscoveryRequest {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:    delta.node,
		TypeUrl: typeUrl,
	}
}

func (delta *deltaHelper) prepareObsReq(obsReq *observeRequest) (*discoverypb.DeltaDiscoveryRequest, error) {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:                   delta.node,
		TypeUrl:                obsReq.typeUrl,
		ResourceNamesSubscribe: obsReq.resourceNames,
	}, nil
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
