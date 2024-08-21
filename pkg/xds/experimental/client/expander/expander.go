// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package expander

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/xds/experimental/client"

	listenerpb "github.com/cilium/proxy/go/envoy/config/listener/v3"
	tcppb "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
)

type tree struct {
	c client.BaseLayer
}

func MakeTree(ctx context.Context, c client.BaseLayer) {
	t := &tree{c}

	id := c.AddResourceWatcher(envoy.ListenerTypeURL, t.processListener)
	slog.Debug("registered", "id", id)

	go func() {
		defer c.RemoveResourceWatcher(id)
		<-ctx.Done()
		slog.Debug("unregister", "id", id)
	}()
}

func (t *tree) processListener(res *xds.VersionedResources) {
	clusters := make([]string, 0)
	for _, r := range res.Resources {
		l, ok := r.(*listenerpb.Listener)
		if !ok {
			continue
		}
		for _, chain := range l.GetFilterChains() {
			if len(chain.GetFilters()) != 1 {
				continue
			}
			filter := chain.GetFilters()[0]

			conf := filter.GetTypedConfig()
			if conf == nil {
				continue
			}

			tcpProxy := &tcppb.TcpProxy{}
			if err := conf.UnmarshalTo(tcpProxy); err != nil {
				continue
			}
			xDSClusterName := tcpProxy.GetCluster()
			if xDSClusterName == "" {
				weightedClusters := tcpProxy.GetWeightedClusters().GetClusters()
				if len(weightedClusters) != 1 {
					continue
				}
				xDSClusterName = weightedClusters[0].GetName()
				if xDSClusterName == "" {
					continue
				}
			}
			clusters = append(clusters, xDSClusterName)
		}
	}
	slog.Debug("observe", "clusters", clusters)
	t.c.Observe(context.Background(), envoy.ClusterTypeURL, clusters)
	t.c.Observe(context.Background(), envoy.EndpointTypeURL, clusters)
}
