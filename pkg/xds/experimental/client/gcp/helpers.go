// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gcp

import (
	"fmt"

	"github.com/google/uuid"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
)

func Node(projectNum int64, mesh string, locality *corepb.Locality, clientID, userAgent string) *corepb.Node {
	nodeId := fmt.Sprintf("projects/%d/networks/mesh:%s/nodes/%s", projectNum, mesh, clientID)
	return &corepb.Node{
		Id:            nodeId,
		UserAgentName: userAgent,
		Locality:      locality,
	}
}

func LocalityFromZone(zone string) *corepb.Locality {
	if len(zone) < 3 {
		return &corepb.Locality{
			Zone: zone,
		}
	}
	return &corepb.Locality{
		Zone:   zone,
		Region: zone[:len(zone)-2],
	}
}

func UniqueNode(projectNum int64, mesh string, zone string) *corepb.Node {
	id := uuid.New()
	return Node(projectNum, mesh, LocalityFromZone(zone), id.String(), "cilium-agent")
}
