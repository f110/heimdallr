package controllers

import (
	"fmt"
	"sync"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var processRepository = &ProcessRepository{data: make(map[string]*LagrangianProxy)}

type ProcessRepository struct {
	sync.Mutex

	client client.Client
	data   map[string]*LagrangianProxy
}

func NewProcessRepository() *ProcessRepository {
	return processRepository
}

func (r *ProcessRepository) Get(spec *proxyv1.Proxy) *LagrangianProxy {
	r.Lock()
	defer r.Unlock()

	if v, ok := r.data[fmt.Sprintf("%s/%s", spec.Namespace, spec.Name)]; ok {
		return v
	}

	v := NewLagrangianProxy(spec, r.client)
	r.data[fmt.Sprintf("%s/%s", spec.Namespace, spec.Name)] = v
	return v
}

func (r *ProcessRepository) SetClient(c client.Client) {
	r.client = c
}
