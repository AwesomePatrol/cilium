// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
)

// watchers is a helper structure for Client focused on [un]registering callbacks on resource changes.
type watchers struct {
	log *slog.Logger

	src xds.ObservableResourceSource

	// mux protects all fields below.
	mux lock.Mutex
	// listeners maps ID to an instance of a listener.
	listeners map[uint64]*listener
	lastID    uint64
}

func newWatchers(log *slog.Logger, src xds.ObservableResourceSource) *watchers {
	return &watchers{
		log:       log,
		src:       src,
		listeners: make(map[uint64]*listener),
	}
}

// WatcherCallback will be called when a new version of a resource it was
// registered on appears. res will contain all resources of this type.
type WatcherCallback func(res *xds.VersionedResources)

// Add registers a callback for a specified typeUrl.
// Returned ID can be used to later unregister the callback.
func (w *watchers) Add(typeUrl string, cb WatcherCallback) uint64 {
	w.mux.Lock()
	defer w.mux.Unlock()

	w.lastID++

	l := &listener{
		typeUrl:   typeUrl,
		cb:        cb,
		log:       w.log.With("listenerID", w.lastID),
		resources: w.src,
		trigger:   make(chan struct{}, 1),
	}
	go l.process()
	w.src.AddResourceVersionObserver(l)
	w.listeners[w.lastID] = l

	return w.lastID
}

// Remove unregisters a callback with given ID. It does nothing if ID is not found.
func (w *watchers) Remove(ID uint64) {
	w.mux.Lock()
	defer w.mux.Unlock()

	l, ok := w.listeners[ID]
	if !ok {
		// Not found or already deleted.
		return
	}
	w.src.RemoveResourceVersionObserver(l)
	delete(w.listeners, ID)
	close(l.trigger)
}
