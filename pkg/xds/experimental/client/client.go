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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/logging/logfields"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	discoverypb "github.com/cilium/proxy/go/envoy/service/discovery/v3"
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

type BaseLayerWithRun interface {
	BaseLayer
	Run(ctx context.Context, conn grpc.ClientConnInterface) error
}

var _ BaseLayerWithRun = (*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])(nil)
var _ BaseLayerWithRun = (*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse])(nil)

type observeRequest struct {
	// For example: "type.googleapis.com/envoy.config.listener.v3.Listener"
	typeUrl       string
	resourceNames []string
}

type XDSClient[ReqT RequestCons, RespT ResponseCons] struct {
	log  *slog.Logger
	opts Options

	observeQueue  chan *observeRequest
	responseQueue chan RespT

	helper Helper[ReqT, RespT]

	// cache stores versioned resources.
	cache *xds.Cache
	// watchers manages callbacks with notification when cache state changes.
	watchers *watchers
}

func NewClient(log *slog.Logger, node *corepb.Node, opts *Options) BaseLayerWithRun {
	// n is used to identify a client to xDS server.
	// It is part of every Request sent on a stream.
	n := proto.Clone(node).(*corepb.Node)
	if opts.UseSOTW {
		c := newClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse](log, opts)
		c.helper = &sotwHelper{n}
		return c
	} else {
		c := newClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse](log, opts)
		c.helper = &deltaHelper{n}
		return c
	}
}

func newClient[ReqT RequestCons, RespT ResponseCons](log *slog.Logger, opts *Options) *XDSClient[ReqT, RespT] {
	cache := xds.NewCache()

	return &XDSClient[ReqT, RespT]{
		log:           log,
		opts:          *opts,
		observeQueue:  make(chan *observeRequest, 1),
		responseQueue: make(chan RespT, 1),
		cache:         cache,
		watchers:      newWatchers(log.With(logFeatureKey, "watchers"), cache),
	}
}

// Run will start an AggregatedDiscoverService stream and process requests
// and responses until provided Context ctx is done or non-retriable error occurs.
func (c *XDSClient[ReqT, RespT]) Run(ctx context.Context, conn grpc.ClientConnInterface) error {
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

func (c *XDSClient[ReqT, RespT]) openAndProcess(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) error {
	trans, err := c.helper.getTransport(ctx, client)
	if err != nil {
		return fmt.Errorf("start transport: %w", err)
	}
	return c.process(ctx, trans)
}

func (c *XDSClient[ReqT, RespT]) process(ctx context.Context, trans transport[ReqT, RespT]) error {
	if err := c.sendInitialDiscoveryRequests(ctx, trans); err != nil {
		return fmt.Errorf("start request routine: %w", err)
	}

	errRespCh := make(chan error, 1)
	go c.fetchResponses(ctx, errRespCh, trans)
	errLoopCh := make(chan error, 1)
	go c.loop(ctx, errLoopCh, trans)

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

func (c *XDSClient[ReqT, RespT]) isStreamRetriableErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return false
	}
	return c.opts.RetryGrpcError(status.Code(err))
}

// sendInitialDiscoveryRequests sends requests for all configured ObservedResources.
// It returns error only when a goroutine wasn't started yet.
func (c *XDSClient[ReqT, RespT]) sendInitialDiscoveryRequests(ctx context.Context, trans transport[ReqT, RespT]) error {
	log := c.log.With(logFeatureKey, "initial-requests")
	for _, typeUrl := range c.opts.BootstrapResources {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req := c.helper.initialReq(typeUrl)
		log.Debug("Send", "req", req)
		err := trans.Send(req)
		if err != nil {
			return fmt.Errorf("initial requests: stream send: %w", err)
		}
	}
	return nil
}

// fetchResponses will pass messages from Recv() calls to queue until Context ctx is done.
func (c *XDSClient[ReqT, RespT]) fetchResponses(ctx context.Context, errCh chan error, trans transport[ReqT, RespT]) {
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
		resp, err := trans.Recv()
		if err != nil {
			log.Error("Failed to receive message", logfields.Error, err)
			errCh <- err
			backoff.Wait(ctx)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case c.responseQueue <- resp:
		}
	}
}

func (c *XDSClient[ReqT, RespT]) getAllResources(typeUrl string) (*xds.VersionedResources, error) {
	return c.cache.GetResources(typeUrl, 0, "", nil)
}

// Observe adds resourceNames to watched resources of a given typeUrl.
// It will be sent to a server asynchronously.
func (c *XDSClient[ReqT, RespT]) Observe(ctx context.Context, typeUrl string, resourceNames []string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.observeQueue <- &observeRequest{typeUrl: typeUrl, resourceNames: resourceNames}:
	}
	return nil
}

// loop will process responses from stream until Context ctx is done.
// Errors are logged and processing continues.
func (c *XDSClient[ReqT, RespT]) loop(ctx context.Context, errCh chan error, trans transport[ReqT, RespT]) {
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
			err := c.handleObserveRequest(obsReq, trans)
			if err != nil {
				log.Error("Send", logfields.Error, err)
				errCh <- err
				backoff.Wait(ctx)
			}
		case resp, ok := <-c.responseQueue:
			if !ok {
				return
			}
			log.Debug("Receive", "resp", resp)
			var err error
			if c.opts.UseSOTW {
				err = c.handleResponseQueue(trans, resp)
			} else {
				err = c.handleDeltaResponseQueue(trans, resp)
			}
			if err != nil {
				log.Error("Failed to handle response", logfields.Error, err)
				errCh <- err
				req := c.helper.resp2nack(resp, err)
				err = trans.Send(req)
				if err != nil {
					log.Error("Failed to send NACK", logfields.Error, err)
				}
				backoff.Wait(ctx)
				continue
			}
		}
	}
}

func (c *XDSClient[ReqT, RespT]) handleObserveRequest(obsReq *observeRequest, trans transport[ReqT, RespT]) error {
	var curr []string
	if c.opts.UseSOTW {
		all, err := c.getAllResources(obsReq.typeUrl)
		if err != nil {
			return fmt.Errorf("get resources: %w", err)
		}
		curr = all.ResourceNames
	}
	req, err := c.helper.prepareObsReq(obsReq, curr)
	if err != nil {
		c.log.Error("Failed to prepare request",
			"observe-request", obsReq,
			logfields.Error, err,
			logFeatureKey, "observe-request-handler",
		)
		return nil
	}
	c.log.Debug("Send", "req", req)
	return trans.Send(req)
}

func (c *XDSClient[ReqT, RespT]) handleResponseQueue(
	trans transport[ReqT, RespT],
	resp RespT) error {

	upsertedResources, err := c.helper.resp2resources(resp)
	if err != nil {
		return fmt.Errorf("handle response: %w", err)
	}
	err = c.upsertAndDeleteMissing(resp.GetTypeUrl(), upsertedResources)
	if err != nil {
		return fmt.Errorf("update resources: %w", err)
	}
	req := c.helper.resp2ack(resp, slices.Collect(maps.Keys(upsertedResources)))
	err = trans.Send(req)
	if err != nil {
		return fmt.Errorf("ACK not sent: %w", err)
	}
	return nil
}

func (c *XDSClient[ReqT, RespT]) handleDeltaResponseQueue(
	trans transport[ReqT, RespT],
	resp RespT,
) error {
	upsertedResources, err := c.helper.resp2resources(resp)
	if err != nil {
		return fmt.Errorf("handle response: %w", err)
	}
	typeUrl := resp.GetTypeUrl()
	deletedResources := c.helper.resp2deleted(resp)
	c.log.Debug("cache TX", "typeUrl", typeUrl, "upserted", upsertedResources, "deleted", deletedResources)
	ver, updated, _ := c.cache.TX(typeUrl, upsertedResources, deletedResources)
	c.log.Debug("cache TX", "typeUrl", typeUrl, "ver", ver, "updated", updated)
	req := c.helper.resp2ack(resp, nil)
	err = trans.Send(req)
	if err != nil {
		return fmt.Errorf("ACK not sent: %w", err)
	}
	return nil
}

func (c *XDSClient[ReqT, RespT]) upsertAndDeleteMissing(typeUrl string, upsertedResources nameToResource) error {
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

func (c *XDSClient[ReqT, RespT]) deletedResources(typeUrl string, curr nameToResource) ([]string, error) {
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

func (c *XDSClient[ReqT, RespT]) AddResourceWatcher(typeUrl string, cb WatcherCallback) uint64 {
	return c.watchers.Add(typeUrl, cb)
}

func (c *XDSClient[ReqT, RespT]) RemoveResourceWatcher(id uint64) {
	c.watchers.Remove(id)
}
