package controllers

import (
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/v1"
)

var processRepository = &ProcessRepository{data: make(map[string]*LagrangianProxy)}

type ProcessRepository struct {
	sync.Mutex

	Log logr.Logger

	client client.Client
	data   map[string]*LagrangianProxy
}

func NewProcessRepository(logger logr.Logger) *ProcessRepository {
	processRepository.Log = logger
	return processRepository
}

func (r *ProcessRepository) Get(spec *proxyv1.Proxy) *LagrangianProxy {
	r.Lock()
	defer r.Unlock()

	if v, ok := r.data[fmt.Sprintf("%s/%s", spec.Namespace, spec.Name)]; ok {
		v.Object = spec
		v.Spec = spec.Spec
		return v
	}

	v := NewLagrangianProxy(spec, r.client, r.Log)
	r.data[fmt.Sprintf("%s/%s", spec.Namespace, spec.Name)] = v
	return v
}

func (r *ProcessRepository) SetClient(c client.Client) {
	r.client = c
}
