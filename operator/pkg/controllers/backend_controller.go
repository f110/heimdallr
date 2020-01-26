/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/v1"
)

// BackendReconciler reconciles a Backend object
type BackendReconciler struct {
	client.Client
	Log               logr.Logger
	Scheme            *runtime.Scheme
	ProcessRepository *ProcessRepository
}

// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends/status,verbs=get;update;patch

func (r *BackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&proxyv1.Backend{}).
		Complete(r)
}

func (r *BackendReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	backend := &proxyv1.Backend{}
	if err := r.Get(context.Background(), req.NamespacedName, backend); err != nil {
		return ctrl.Result{}, err
	}

	defList := &proxyv1.ProxyList{}
	if err := r.List(context.Background(), defList); err != nil {
		return ctrl.Result{}, err
	}

	targets := make([]proxyv1.Proxy, 0)
Item:
	for _, v := range defList.Items {
		for k := range v.Spec.BackendSelector.MatchLabels {
			value, ok := backend.ObjectMeta.Labels[k]
			if !ok || v.Spec.BackendSelector.MatchLabels[k] != value {
				continue Item
			}
		}

		targets = append(targets, v)
	}

	for _, v := range targets {
		lp := r.ProcessRepository.Get(&v)
		if err := r.reconcileConfig(lp); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *BackendReconciler) reconcileConfig(lp *LagrangianProxy) error {
	lp.Lock()
	defer lp.Unlock()

	configMap, err := lp.ReverseProxyConfig()
	if err != nil {
		return err
	}
	orig := configMap.DeepCopy()
	_, err = ctrl.CreateOrUpdate(context.Background(), r, configMap, func() error {
		configMap.Data = orig.Data

		return ctrl.SetControllerReference(lp.Object, configMap, r.Scheme)
	})
	if err != nil {
		return err
	}

	cert, err := lp.Certificate()
	if err != nil {
		return err
	}
	origC := cert.DeepCopy()
	_, err = ctrl.CreateOrUpdate(context.Background(), r, cert, func() error {
		cert.Spec = origC.Spec

		return ctrl.SetControllerReference(lp.Object, cert, r.Scheme)
	})

	return nil
}
