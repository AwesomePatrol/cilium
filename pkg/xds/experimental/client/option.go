// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"time"

	"github.com/cilium/cilium/pkg/envoy"

	"google.golang.org/grpc/codes"
)

type Options struct {
	MinBackoff         time.Duration
	MaxBackoff         time.Duration
	BackoffReset       time.Duration
	BootstrapResources []string
	UseSOTW            bool `mapstructure:"xds-use-sotw-protocol"`
	RetryConnection    bool
	RetryGrpcError     func(code codes.Code) (retry bool)
}

var Defaults = &Options{
	MinBackoff:   time.Second,
	MaxBackoff:   time.Minute,
	BackoffReset: 2 * time.Minute,
	// BootstrapResources should consist of subset of Listener, Clusters based on:
	// https://www.envoyproxy.io/docs/envoy/v1.31.0/api-docs/xds_protocol#client-configuration
	BootstrapResources: []string{envoy.ListenerTypeURL, envoy.ClusterTypeURL},
	RetryGrpcError: func(code codes.Code) bool {
		switch code {
		case codes.PermissionDenied, codes.Aborted, codes.Unauthenticated, codes.Unavailable, codes.Canceled:
			return false
		}
		return true
	},
}
