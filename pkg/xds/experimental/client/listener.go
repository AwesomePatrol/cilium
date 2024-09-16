// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

// listener is a helper structure for watchers focused on handling a single, registered callback.
type listener struct {
	typeUrl string
	cb      WatcherCallback
	trigger chan struct{}

	log       *slog.Logger
	resources xds.ResourceSource
}

var _ xds.ResourceVersionObserver = (*listener)(nil)

// HandleNewResourceVersion implements xds.ResourceVersionObserver.
// It triggers the callback process.
func (l *listener) HandleNewResourceVersion(typeUrl string, _ uint64) {
	if typeUrl != l.typeUrl {
		return
	}
	select {
	case l.trigger <- struct{}{}:
	default:
	}
}

// process waits for the listener trigger (new resource version) and invokes the callback function.
// It needs to be done asynchronyously from HandleNewResourceVersion, because
// the cache invoking the function holds a lock on the resources.
func (l *listener) process() {
	for range l.trigger {
		resVer, err := l.resources.GetResources(l.typeUrl, 0, "", nil)
		if err != nil {
			l.log.Error("Failed to fetch resource", "err", err)
			continue
		}

		l.log.Debug("Invoke callback")
		l.cb(resVer)
	}
}
