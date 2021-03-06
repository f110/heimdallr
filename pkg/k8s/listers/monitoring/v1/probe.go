/*

MIT License

Copyright (c) 2019 Fumihiro Ito

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/
// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ProbeLister helps list Probes.
// All objects returned here must be treated as read-only.
type ProbeLister interface {
	// List lists all Probes in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.Probe, err error)
	// Probes returns an object that can list and get Probes.
	Probes(namespace string) ProbeNamespaceLister
	ProbeListerExpansion
}

// probeLister implements the ProbeLister interface.
type probeLister struct {
	indexer cache.Indexer
}

// NewProbeLister returns a new ProbeLister.
func NewProbeLister(indexer cache.Indexer) ProbeLister {
	return &probeLister{indexer: indexer}
}

// List lists all Probes in the indexer.
func (s *probeLister) List(selector labels.Selector) (ret []*v1.Probe, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.Probe))
	})
	return ret, err
}

// Probes returns an object that can list and get Probes.
func (s *probeLister) Probes(namespace string) ProbeNamespaceLister {
	return probeNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ProbeNamespaceLister helps list and get Probes.
// All objects returned here must be treated as read-only.
type ProbeNamespaceLister interface {
	// List lists all Probes in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.Probe, err error)
	// Get retrieves the Probe from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.Probe, error)
	ProbeNamespaceListerExpansion
}

// probeNamespaceLister implements the ProbeNamespaceLister
// interface.
type probeNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all Probes in the indexer for a given namespace.
func (s probeNamespaceLister) List(selector labels.Selector) (ret []*v1.Probe, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.Probe))
	})
	return ret, err
}

// Get retrieves the Probe from the indexer for a given namespace and name.
func (s probeNamespaceLister) Get(name string) (*v1.Probe, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("probe"), name)
	}
	return obj.(*v1.Probe), nil
}
