// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package gcp_test

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/xds/experimental/client"
	"github.com/cilium/cilium/pkg/xds/experimental/client/expander"
	"github.com/cilium/cilium/pkg/xds/experimental/client/gcp"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/google"
	"google.golang.org/grpc/credentials/oauth"
)

var testFlags = struct {
	projectNum int64
	mesh       string
	tdEndpoint string
	zone       string
	sotw       bool
}{
	tdEndpoint: "dns:///trafficdirector.googleapis.com:443",
}

func init() {
	flag.StringVar(&testFlags.tdEndpoint, "td-endpoint", testFlags.tdEndpoint, "Endpoint of Traffic Director")
	flag.StringVar(&testFlags.mesh, "mesh", testFlags.mesh, "Network Services' Mesh")
	flag.Int64Var(&testFlags.projectNum, "project-num", testFlags.projectNum, "Project number")
	flag.StringVar(&testFlags.zone, "zone", testFlags.zone, "Zone component of a locality of a node")
	flag.BoolVar(&testFlags.sotw, "sotw", testFlags.sotw, "Use SoTW version of the xDS protocol")
}

// This lets you connect to existing mesh and observe Request/Response
// exchange with Traffic Director server. The client will cleanly terminate
// after 20 seconds.
//
// Example command:
//
//	go test -v ./pkg/xds/client/... \
//	  -project-num 157897283967 \
//	  -zone us-central1-c \
//	  -mesh wora-mesh-4067
func TestClient(t *testing.T) {
	if testFlags.tdEndpoint == "" {
		t.Skip("td-endpoint must be set")
	}
	if testFlags.projectNum == 0 {
		t.Skip("project-num must be set")
	}
	if testFlags.zone == "" {
		t.Skip("zone must be set")
	}
	if testFlags.mesh == "" {
		t.Skip("mesh must be set")
	}

	slog.SetLogLoggerLevel(slog.LevelDebug)
	cOpts := client.Defaults
	cOpts.UseSOTW = testFlags.sotw
	cOpts.RetryConnection = true
	c := client.NewClient(slog.Default(), gcp.UniqueNode(testFlags.projectNum, testFlags.mesh, testFlags.zone), cOpts)

	ctx, cancel := context.WithCancel(context.Background())
	perRPCCreds, err := oauth.NewApplicationDefault(ctx)
	if err != nil {
		t.Fatalf("Error getting credentials: %v", err)
	}
	expander.MakeTree(ctx, c)

	creds := google.NewDefaultCredentialsWithOptions(google.DefaultCredentialsOptions{PerRPCCreds: perRPCCreds})
	gOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds.TransportCredentials()),
		grpc.WithPerRPCCredentials(creds.PerRPCCredentials()),
	}
	conn, err := grpc.NewClient(testFlags.tdEndpoint, gOpts...)
	if err != nil {
		log.Fatalf("Error dialing xDS server: %v", err)
	}
	defer conn.Close()

	go c.Run(ctx, conn)

	time.Sleep(20 * time.Second)
	cancel()
}
