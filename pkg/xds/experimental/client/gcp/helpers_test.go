// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gcp

import (
	"strings"
	"testing"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
)

func testNode() *corepb.Node {
	return UniqueNode(1, "test-mesh", "test-zone-z")
}

func TestUniqueNode(t *testing.T) {
	got := testNode()
	prefix := "projects/1/networks/mesh:test-mesh/nodes/"
	if !strings.HasPrefix(got.Id, prefix) {
		t.Errorf("nodeID = %q, should start with = %q", got.Id, prefix)
	}
	if want, got := "test-zone-z", got.GetLocality().GetZone(); got != want {
		t.Errorf("zone = %q, want = %q", got, want)
	}
	if want, got := "test-zone", got.GetLocality().GetRegion(); got != want {
		t.Errorf("region = %q, want = %q", got, want)
	}
}
