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
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/v1"
)

// RpcPermissionReconciler reconciles a RpcPermission object
type RpcPermissionReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=proxy.f110.dev,resources=rpcpermissions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=rpcpermissions/status,verbs=get;update;patch

func (r *RpcPermissionReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	permission := &proxyv1.RpcPermission{}
	if err := r.Get(context.Background(), req.NamespacedName, permission); err != nil && errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	defList := &proxyv1.ProxyList{}
	if err := r.List(context.Background(), defList); err != nil {
		return ctrl.Result{}, err
	}

	targets := make([]proxyv1.Proxy, 0)
Item:
	for _, v := range defList.Items {
		// When permission.Labels is nil, it was deleted.
		// Re-generate config file to whole targets.
		if permission.Labels != nil {
			for k := range v.Spec.RpcPermissionSelector.MatchLabels {
				value, ok := permission.ObjectMeta.Labels[k]
				if !ok || v.Spec.RpcPermissionSelector.MatchLabels[k] != value {
					continue Item
				}
			}
		}

		targets = append(targets, v)
	}

	for _, v := range targets {
		lp := NewLagrangianProxy(&v, r.Client, r.Log)
		if err := r.reconcileConfig(lp); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *RpcPermissionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&proxyv1.RpcPermission{}).
		Complete(r)
}

func (r *RpcPermissionReconciler) reconcileConfig(lp *LagrangianProxy) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
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

		return nil
	})
}
