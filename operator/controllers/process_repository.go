package controllers

import (
	"fmt"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/api/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var processRepository = &ProcessRepository{data: make(map[string]*LagrangianProxy)}

type ProcessRepository struct {
	client client.Client
	data   map[string]*LagrangianProxy
}

func NewProcessRepository() *ProcessRepository {
	return processRepository
}

func (r *ProcessRepository) Get(spec *proxyv1.LagrangianProxy) *LagrangianProxy {
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
