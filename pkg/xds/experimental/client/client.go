// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/logging/logfields"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	discoverypb "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
)

const logFeatureKey = "feature"

// BaseLayer is the public interface of xDS client.
type BaseLayer interface {
	// Observe adds resources of given type url and names to the attention set
	// of the client.
	Observe(ctx context.Context, typeUrl string, resourceNames []string) error

	// AddResourceWatcher registers a callback cb that will be invoked every
	// time a resource with given type url changes.
	AddResourceWatcher(typeUrl string, cb WatcherCallback) uint64

	// RemoveResourceWatcher deletes callback registered with given id.
	RemoveResourceWatcher(id uint64)
}

var _ BaseLayer = (*XDSClient)(nil)

type observeRequest struct {
	// For example: "type.googleapis.com/envoy.config.listener.v3.Listener"
	typeUrl       string
	resourceNames []string
}

type XDSClient struct {
	// node is used to identify a client to xDS server.
	// It is part of every Request sent on a stream.
	node *corepb.Node
	log  *slog.Logger
	opts Options

	observeQueue       chan *observeRequest
	responseQueue      chan *discoverypb.DiscoveryResponse
	deltaResponseQueue chan *discoverypb.DeltaDiscoveryResponse

	// cache stores versioned resources.
	cache *xds.Cache
	// watchers manages callbacks with notification when cache state changes.
	watchers *watchers
}

func NewClient(log *slog.Logger, node *corepb.Node, opts *Options) *XDSClient {
	cache := xds.NewCache()

	c := &XDSClient{
		node:               proto.Clone(node).(*corepb.Node),
		log:                log,
		opts:               *opts,
		observeQueue:       make(chan *observeRequest, 1),
		responseQueue:      make(chan *discoverypb.DiscoveryResponse, 1),
		deltaResponseQueue: make(chan *discoverypb.DeltaDiscoveryResponse, 1),
		cache:              cache,
		watchers:           newWatchers(log.With(logFeatureKey, "watchers"), cache),
	}
	return c
}

// Run will start an AggregatedDiscoverService stream and process requests
// and responses until provided Context ctx is done or non-retriable error occurs.
func (c *XDSClient) Run(ctx context.Context, conn grpc.ClientConnInterface) error {
	backoff := backoff.Exponential{
		Min:        c.opts.MinBackoff,
		Max:        c.opts.MaxBackoff,
		ResetAfter: c.opts.BackoffReset,
		Jitter:     true,
		Name:       "xds-client-conn",
	}
	client := discoverypb.NewAggregatedDiscoveryServiceClient(conn)

	for {
		ctxConn, cancelConn := context.WithCancel(ctx)

		err := c.openAndProcess(ctxConn, client)

		cancelConn()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !c.opts.RetryConnection {
			return err
		}
		c.log.Error("Retrying connection", logfields.Error, err)
		err = backoff.Wait(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("connection retry backoff: %w", err)
			}
		}
	}
}

func (c *XDSClient) openAndProcess(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) error {
	if c.opts.UseSOTW {
		stream, err := client.StreamAggregatedResources(ctx, grpc.WaitForReady(true))
		if err != nil {
			return fmt.Errorf("start stream: %w", err)
		}
		return c.process(ctx, stream, nil)
	} else {
		delta, err := client.DeltaAggregatedResources(ctx, grpc.WaitForReady(true))
		if err != nil {
			return fmt.Errorf("start delta: %w", err)
		}
		return c.process(ctx, nil, delta)
	}
}

func (c *XDSClient) process(
	ctx context.Context,
	stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient,
	delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient,
) error {
	if err := c.sendInitialDiscoveryRequests(ctx, stream, delta); err != nil {
		return fmt.Errorf("start request routine: %w", err)
	}

	errRespCh := make(chan error, 1)
	go c.fetchResponses(ctx, errRespCh, stream, delta)
	errLoopCh := make(chan error, 1)
	go c.loop(ctx, errLoopCh, stream, delta)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errRespCh:
			if !ok {
				return fmt.Errorf("process responses: terminated")
			}
			if c.isStreamRetriableErr(err) {
				continue
			}
			return fmt.Errorf("process responses: %w", err)
		case err, ok := <-errLoopCh:
			if !ok {
				return fmt.Errorf("process loop: terminated")
			}
			if c.isStreamRetriableErr(err) {
				continue
			}
			return fmt.Errorf("process loop: %w", err)
		}
	}
}

func (c *XDSClient) isStreamRetriableErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return false
	}
	return c.opts.RetryGrpcError(status.Code(err))
}

// sendInitialDiscoveryRequests sends requests for all configured ObservedResources.
// It returns error only when a goroutine wasn't started yet.
func (c *XDSClient) sendInitialDiscoveryRequests(ctx context.Context,
	stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient,
	delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient,
) error {
	log := c.log.With(logFeatureKey, "initial-requests")
	for _, typeUrl := range c.opts.BootstrapResources {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var err error
		if c.opts.UseSOTW {
			req := &discoverypb.DiscoveryRequest{
				Node:    c.node,
				TypeUrl: typeUrl,
			}
			log.Debug("Stream send", "req", req)
			err = stream.Send(req)
		} else {
			req := &discoverypb.DeltaDiscoveryRequest{
				Node:    c.node,
				TypeUrl: typeUrl,
			}
			log.Debug("Delta send", "req", req)
			err = delta.Send(req)
		}
		if err != nil {
			return fmt.Errorf("initial requests: stream send: %w", err)
		}
	}
	return nil
}

// fetchResponses will pass messages from Recv() calls to queue until Context ctx is done.
func (c *XDSClient) fetchResponses(ctx context.Context, errCh chan error,
	stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient,
	delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient,
) {
	defer close(errCh)
	log := c.log.With(logFeatureKey, "fetch-responses")
	backoff := backoff.Exponential{
		Min:        c.opts.MinBackoff,
		Max:        c.opts.MaxBackoff,
		ResetAfter: c.opts.BackoffReset,
		Jitter:     true,
		Name:       "xds-client-fetch-responses",
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if c.opts.UseSOTW {
			resp, err := stream.Recv()
			if err != nil {
				log.Error("Failed to receive message from stream", logfields.Error, err)
				errCh <- err
				backoff.Wait(ctx)
				continue
			}
			select {
			case <-ctx.Done():
				return
			case c.responseQueue <- resp:
			}
		} else {
			resp, err := delta.Recv()
			if err != nil {
				log.Error("Failed to receive message from stream", logfields.Error, err)
				errCh <- err
				backoff.Wait(ctx)
				continue
			}
			select {
			case <-ctx.Done():
				return
			case c.deltaResponseQueue <- resp:
			}
		}
	}
}

func (c *XDSClient) getAllResources(typeUrl string) (*xds.VersionedResources, error) {
	return c.cache.GetResources(typeUrl, 0, "", nil)
}

// Observe adds resourceNames to watched resources of a given typeUrl.
// It will be sent to a server asynchronously.
func (c *XDSClient) Observe(ctx context.Context, typeUrl string, resourceNames []string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.observeQueue <- &observeRequest{typeUrl: typeUrl, resourceNames: resourceNames}:
	}
	return nil
}

func (c *XDSClient) prepareRequest(obsReq *observeRequest) (*discoverypb.DiscoveryRequest, error) {
	curr, err := c.getAllResources(obsReq.typeUrl)
	if err != nil {
		return nil, fmt.Errorf("get resources: %w", err)
	}
	reqResourceNames := sets.Set[string]{}
	reqResourceNames.Insert(curr.ResourceNames...)
	reqResourceNames.Insert(obsReq.resourceNames...)

	return &discoverypb.DiscoveryRequest{
		Node:          c.node,
		TypeUrl:       obsReq.typeUrl,
		ResourceNames: slices.Collect(maps.Keys(reqResourceNames)),
	}, nil
}

// loop will process responses from stream until Context ctx is done.
// Errors are logged and processing continues.
func (c *XDSClient) loop(ctx context.Context, errCh chan error,
	stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient,
	delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient,
) {
	defer close(errCh)
	log := c.log.With(logFeatureKey, "loop")
	backoff := backoff.Exponential{
		Min:        c.opts.MinBackoff,
		Max:        c.opts.MaxBackoff,
		ResetAfter: c.opts.BackoffReset,
		Jitter:     true,
		Name:       "xds-client-loop",
	}
	for {
		select {
		case <-ctx.Done():
			return
		case obsReq, ok := <-c.observeQueue:
			if !ok {
				return
			}
			err := c.handleObserveRequest(obsReq, stream, delta)
			if err != nil {
				log.Error("Stream/Delta send", logfields.Error, err)
				errCh <- err
				backoff.Wait(ctx)
			}
		case resp, ok := <-c.responseQueue:
			if !ok {
				return
			}
			log.Debug("Stream receive", "resp", resp)
			err := c.handleResponseQueue(ctx, stream, resp)
			if err != nil {
				log.Error("Failed to handle response", logfields.Error, err)
				errCh <- err
				err := c.sendNACK(ctx, stream, resp, err)
				if err != nil {
					log.Error("Failed to send NACK", logfields.Error, err)
				}
				backoff.Wait(ctx)
				continue
			}
		case resp, ok := <-c.deltaResponseQueue:
			if !ok {
				return
			}
			log.Debug("Delta receive", "resp", resp)
			err := c.handleDeltaResponseQueue(ctx, delta, resp)
			if err != nil {
				log.Error("Failed to handle response", logfields.Error, err)
				errCh <- err
				err := c.sendDeltaNACK(ctx, delta, resp, err)
				if err != nil {
					log.Error("Failed to send NACK", logfields.Error, err)
				}
				backoff.Wait(ctx)
				continue
			}
		}
	}
}

func (c *XDSClient) handleObserveRequest(
	obsReq *observeRequest,
	stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient,
	delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient) error {
	if c.opts.UseSOTW {
		var req *discoverypb.DiscoveryRequest
		req, err := c.prepareRequest(obsReq)
		if err != nil {
			c.log.Error("Failed to prepare request",
				"observe-request", obsReq,
				logfields.Error, err,
				logFeatureKey, "observe-request-handler",
			)
			return nil
		}
		c.log.Debug("Stream send", "req", req)
		return stream.Send(req)
	} else {
		req := &discoverypb.DeltaDiscoveryRequest{
			Node:                   c.node,
			TypeUrl:                obsReq.typeUrl,
			ResourceNamesSubscribe: obsReq.resourceNames,
		}
		c.log.Debug("Delta send",
			"req", req,
			logFeatureKey, "observe-request-handler",
		)
		return delta.Send(req)
	}
}

func (c *XDSClient) handleResponseQueue(
	ctx context.Context,
	stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient,
	resp *discoverypb.DiscoveryResponse) error {

	upsertedResources, err := c.handleResponse(resp)
	if err != nil {
		return fmt.Errorf("handle response: %w", err)
	}
	err = c.upsertAndDeleteMissing(resp.GetTypeUrl(), upsertedResources)
	if err != nil {
		return fmt.Errorf("update resources: %w", err)
	}
	err = c.sendACK(ctx, stream, resp, upsertedResources)
	if err != nil {
		return fmt.Errorf("ACK not send: %w", err)
	}
	return nil
}

func (c *XDSClient) handleDeltaResponseQueue(
	ctx context.Context,
	delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient,
	resp *discoverypb.DeltaDiscoveryResponse,
) error {
	upsertedResources, err := c.handleDeltaResponse(resp)
	if err != nil {
		return fmt.Errorf("handle response: %w", err)
	}
	typeUrl := resp.GetTypeUrl()
	respDelRes := resp.GetRemovedResourceNames()
	deletedResources := make([]string, 0, len(respDelRes))
	for _, res := range respDelRes {
		deletedResources = append(deletedResources, res.GetName())
	}
	c.log.Debug("cache TX", "typeUrl", typeUrl, "upserted", upsertedResources, "deleted", deletedResources)
	ver, updated, _ := c.cache.TX(typeUrl, upsertedResources, deletedResources)
	c.log.Debug("cache TX", "typeUrl", typeUrl, "ver", ver, "updated", updated)
	err = c.sendDeltaACK(ctx, delta, resp)
	if err != nil {
		return fmt.Errorf("ACK not send: %w", err)
	}
	return nil
}

// nameToResource maps a resource name to a proto representation of the resource.
type nameToResource map[string]proto.Message

func (c *XDSClient) handleDeltaResponse(resp *discoverypb.DeltaDiscoveryResponse) (nameToResource, error) {
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

// handleResponse decodes the resources based on TypeUrl and updates the cache.
func (c *XDSClient) handleResponse(resp *discoverypb.DiscoveryResponse) (nameToResource, error) {
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

func (c *XDSClient) upsertAndDeleteMissing(typeUrl string, upsertedResources nameToResource) error {
	var err error
	var deletedResources []string
	if typeUrl == envoy.ListenerTypeURL || typeUrl == envoy.ClusterTypeURL {
		deletedResources, err = c.deletedResources(typeUrl, upsertedResources)
		if err != nil {
			return err
		}
	}
	c.log.Debug("cache TX", "typeUrl", typeUrl, "upserted", slices.Collect(maps.Keys(upsertedResources)), "deleted", deletedResources)
	ver, updated, _ := c.cache.TX(typeUrl, upsertedResources, deletedResources)
	c.log.Debug("cache TX", "typeUrl", typeUrl, "ver", ver, "updated", updated)

	if typeUrl == envoy.ClusterTypeURL {
		deletedResources, err := c.deletedResources(envoy.EndpointTypeURL, upsertedResources)
		if err != nil {
			return fmt.Errorf("delete endpoints (when processing clusters): %w", err)
		}
		c.log.Debug("cache TX", "typeUrl", typeUrl, "upserted", slices.Collect(maps.Keys(upsertedResources)), "deleted", deletedResources)
		ver, updated, _ := c.cache.TX(envoy.EndpointTypeURL, nil, deletedResources)
		c.log.Debug("cache TX", "typeUrl", typeUrl, "ver", ver, "updated", updated)
	}
	return nil
}

func (c *XDSClient) deletedResources(typeUrl string, curr nameToResource) ([]string, error) {
	old, err := c.getAllResources(typeUrl)
	if err != nil {
		// In version 1.14 GetResources doesn't return any error for these arguments.
		return nil, fmt.Errorf("get old resources: %w", err)
	}
	deletedResources := make([]string, 0, len(old.ResourceNames))
	for _, name := range old.ResourceNames {
		if _, ok := curr[name]; ok {
			continue
		}
		deletedResources = append(deletedResources, name)
	}
	return deletedResources, nil
}

func (c *XDSClient) sendACK(
	ctx context.Context,
	stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient,
	resp *discoverypb.DiscoveryResponse,
	upsertedResources nameToResource) error {
	resourceNames := slices.Collect(maps.Keys(upsertedResources))
	req := &discoverypb.DiscoveryRequest{
		Node:          c.node,
		VersionInfo:   resp.GetVersionInfo(),
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ResourceNames: resourceNames,
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		c.log.Debug("Send ACK", "req", req)
		if err := stream.Send(req); err != nil {
			return fmt.Errorf("will not ACK: send: %w", err)
		}
		return nil
	}
}

func (c *XDSClient) sendDeltaACK(ctx context.Context, delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient, resp *discoverypb.DeltaDiscoveryResponse) error {
	req := &discoverypb.DeltaDiscoveryRequest{
		Node:          c.node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		c.log.Debug("Send ACK", "req", req)
		if err := delta.Send(req); err != nil {
			return fmt.Errorf("will not ACK: send: %w", err)
		}
		return nil
	}
}

func (c *XDSClient) sendNACK(ctx context.Context, stream discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient, resp *discoverypb.DiscoveryResponse, detail error) error {
	req := &discoverypb.DiscoveryRequest{
		Node:          c.node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ErrorDetail: &statuspb.Status{
			Code:    int32(codes.Unknown),
			Message: detail.Error(),
		},
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		c.log.Debug("Send NACK", "req", req)
		err := stream.Send(req)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *XDSClient) sendDeltaNACK(ctx context.Context, delta discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient, resp *discoverypb.DeltaDiscoveryResponse, detail error) error {
	req := &discoverypb.DeltaDiscoveryRequest{
		Node:          c.node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ErrorDetail: &statuspb.Status{
			Code:    int32(codes.Unknown),
			Message: detail.Error(),
		},
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		c.log.Debug("Send NACK", "req", req)
		err := delta.Send(req)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *XDSClient) AddResourceWatcher(typeUrl string, cb WatcherCallback) uint64 {
	return c.watchers.Add(typeUrl, cb)
}

func (c *XDSClient) RemoveResourceWatcher(id uint64) {
	c.watchers.Remove(id)
}
