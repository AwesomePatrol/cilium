// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v2alpha1

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// CiliumFlowLogLister helps list CiliumFlowLogs.
// All objects returned here must be treated as read-only.
type CiliumFlowLogLister interface {
	// List lists all CiliumFlowLogs in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2alpha1.CiliumFlowLog, err error)
	// Get retrieves the CiliumFlowLog from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2alpha1.CiliumFlowLog, error)
	CiliumFlowLogListerExpansion
}

// ciliumFlowLogLister implements the CiliumFlowLogLister interface.
type ciliumFlowLogLister struct {
	indexer cache.Indexer
}

// NewCiliumFlowLogLister returns a new CiliumFlowLogLister.
func NewCiliumFlowLogLister(indexer cache.Indexer) CiliumFlowLogLister {
	return &ciliumFlowLogLister{indexer: indexer}
}

// List lists all CiliumFlowLogs in the indexer.
func (s *ciliumFlowLogLister) List(selector labels.Selector) (ret []*v2alpha1.CiliumFlowLog, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v2alpha1.CiliumFlowLog))
	})
	return ret, err
}

// Get retrieves the CiliumFlowLog from the index for a given name.
func (s *ciliumFlowLogLister) Get(name string) (*v2alpha1.CiliumFlowLog, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v2alpha1.Resource("ciliumflowlog"), name)
	}
	return obj.(*v2alpha1.CiliumFlowLog), nil
}
