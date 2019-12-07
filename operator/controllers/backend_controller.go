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

	proxyv1 "github.com/f110/lagrangian-proxy/operator/api/v1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// BackendReconciler reconciles a Backend object
type BackendReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends/status,verbs=get;update;patch

func (r *BackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&proxyv1.Backend{}).
		Complete(r)
}

func (r *BackendReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("lagrangianproxy", req.NamespacedName)

	backend := &proxyv1.Backend{}
	if err := r.Get(context.Background(), req.NamespacedName, backend); err != nil {
		return ctrl.Result{}, err
	}

	defList := &proxyv1.LagrangianProxyList{}
	if err := r.List(context.Background(), defList); err != nil {
		return ctrl.Result{}, err
	}

	targets := make([]proxyv1.LagrangianProxy, 0)
Item:
	for _, v := range defList.Items {
		for k := range v.Spec.BackendSelector.MatchLabels {
			if value, ok := backend.ObjectMeta.Labels[k]; !ok && v.Spec.BackendSelector.MatchLabels[k] != value {
				continue Item
			}
		}

		targets = append(targets, v)
	}

	for _, v := range targets {
		if err := ConfigReconcile(r, r.Scheme, &v); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}
