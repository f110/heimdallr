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

package v1beta1

import (
	v1beta1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// CertificateLister helps list Certificates.
// All objects returned here must be treated as read-only.
type CertificateLister interface {
	// List lists all Certificates in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.Certificate, err error)
	// Certificates returns an object that can list and get Certificates.
	Certificates(namespace string) CertificateNamespaceLister
	CertificateListerExpansion
}

// certificateLister implements the CertificateLister interface.
type certificateLister struct {
	indexer cache.Indexer
}

// NewCertificateLister returns a new CertificateLister.
func NewCertificateLister(indexer cache.Indexer) CertificateLister {
	return &certificateLister{indexer: indexer}
}

// List lists all Certificates in the indexer.
func (s *certificateLister) List(selector labels.Selector) (ret []*v1beta1.Certificate, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.Certificate))
	})
	return ret, err
}

// Certificates returns an object that can list and get Certificates.
func (s *certificateLister) Certificates(namespace string) CertificateNamespaceLister {
	return certificateNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// CertificateNamespaceLister helps list and get Certificates.
// All objects returned here must be treated as read-only.
type CertificateNamespaceLister interface {
	// List lists all Certificates in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1beta1.Certificate, err error)
	// Get retrieves the Certificate from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1beta1.Certificate, error)
	CertificateNamespaceListerExpansion
}

// certificateNamespaceLister implements the CertificateNamespaceLister
// interface.
type certificateNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all Certificates in the indexer for a given namespace.
func (s certificateNamespaceLister) List(selector labels.Selector) (ret []*v1beta1.Certificate, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.Certificate))
	})
	return ret, err
}

// Get retrieves the Certificate from the indexer for a given namespace and name.
func (s certificateNamespaceLister) Get(name string) (*v1beta1.Certificate, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("certificate"), name)
	}
	return obj.(*v1beta1.Certificate), nil
}
