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

package v1alpha2

import (
	v1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ClusterIssuerLister helps list ClusterIssuers.
type ClusterIssuerLister interface {
	// List lists all ClusterIssuers in the indexer.
	List(selector labels.Selector) (ret []*v1alpha2.ClusterIssuer, err error)
	// Get retrieves the ClusterIssuer from the index for a given name.
	Get(name string) (*v1alpha2.ClusterIssuer, error)
	ClusterIssuerListerExpansion
}

// clusterIssuerLister implements the ClusterIssuerLister interface.
type clusterIssuerLister struct {
	indexer cache.Indexer
}

// NewClusterIssuerLister returns a new ClusterIssuerLister.
func NewClusterIssuerLister(indexer cache.Indexer) ClusterIssuerLister {
	return &clusterIssuerLister{indexer: indexer}
}

// List lists all ClusterIssuers in the indexer.
func (s *clusterIssuerLister) List(selector labels.Selector) (ret []*v1alpha2.ClusterIssuer, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha2.ClusterIssuer))
	})
	return ret, err
}

// Get retrieves the ClusterIssuer from the index for a given name.
func (s *clusterIssuerLister) Get(name string) (*v1alpha2.ClusterIssuer, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha2.Resource("clusterissuer"), name)
	}
	return obj.(*v1alpha2.ClusterIssuer), nil
}