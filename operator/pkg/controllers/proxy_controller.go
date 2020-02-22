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
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	cconfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/v1"
)

var (
	ErrRetryReconcile = errors.New("controller: retry reconcile")
)

// ProxyReconciler reconciles a Proxy object
type ProxyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme

	enablePrometheusOperator bool
	enableEtcdBackupOperator bool
}

// +kubebuilder:rbac:groups=proxy.f110.dev,resources=proxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=proxies/status,verbs=get;update;patch

func (r *ProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := r.checkOperator(); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&proxyv1.Proxy{}).
		Complete(r)
}

func (r *ProxyReconciler) checkOperator() error {
	cfg, err := cconfig.GetConfig()
	if err != nil {
		return err
	}
	dc := discovery.NewDiscoveryClientForConfigOrDie(cfg)
	_, apiList, err := dc.ServerGroupsAndResources()
	if err != nil {
		return err
	}

	if err := r.existCustomResource(apiList, "etcd.database.coreos.com/v1beta2", "EtcdCluster"); err != nil {
		return err
	}
	if err := r.existCustomResource(apiList, "cert-manager.io/v1alpha2", "Certificate"); err != nil {
		return err
	}

	r.discoverPrometheusOperator(apiList)
	r.discoverEtcdBackupOperator(apiList)

	return nil
}

func (r *ProxyReconciler) existCustomResource(apiList []*metav1.APIResourceList, groupVersion, kind string) error {
	for _, v := range apiList {
		if v.GroupVersion == groupVersion {
			for _, v := range v.APIResources {
				if v.Kind == kind {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("controllers: %s/%s not found", groupVersion, kind)
}

func (r *ProxyReconciler) discoverPrometheusOperator(apiList []*metav1.APIResourceList) {
	for _, v := range apiList {
		if v.GroupVersion == "monitoring.coreos.com/v1" {
			r.enablePrometheusOperator = true
			return
		}
	}
}

func (r *ProxyReconciler) discoverEtcdBackupOperator(apiList []*metav1.APIResourceList) {
	for _, v := range apiList {
		if v.GroupVersion == "etcd.database.coreos.com/v1beta2" {
			for _, v := range v.APIResources {
				if v.Kind == "EtcdBackup" {
					r.enableEtcdBackupOperator = true
					return
				}
			}
		}
	}
}

func (r *ProxyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	r.Log.Info("Request reconcile")
	def := &proxyv1.Proxy{}
	if err := r.Get(context.Background(), req.NamespacedName, def); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	lp := NewLagrangianProxy(def, r.Client, r.Log)
	if requeue, err := r.preSetup(lp); err != nil {
		return ctrl.Result{Requeue: requeue, RequeueAfter: 30 * time.Second}, nil
	}

	if err := r.ReconcileRPCServer(lp); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.ReconcileDashboard(lp); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.ReconcileMainProcess(lp); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.FinishReconcile(lp); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ProxyReconciler) FinishReconcile(lp *LagrangianProxy) error {
	lp.Object.Status.Ready = true
	lp.Object.Status.Phase = "Running"
	return r.Update(context.Background(), lp.Object)
}

func (r *ProxyReconciler) reconcileProcess(lp *LagrangianProxy, objs *process) error {
	if objs.Deployment != nil {
		orig := objs.Deployment.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, objs.Deployment, func() error {
			objs.Deployment.Spec = orig.Spec

			return ctrl.SetControllerReference(lp.Object, objs.Deployment, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	if objs.PodDisruptionBudget != nil {
		orig := objs.PodDisruptionBudget.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, objs.PodDisruptionBudget, func() error {
			objs.PodDisruptionBudget.Spec = orig.Spec

			return ctrl.SetControllerReference(lp.Object, objs.PodDisruptionBudget, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	for _, svc := range objs.Service {
		if svc == nil {
			continue
		}

		orig := svc.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, svc, func() error {
			svc.Labels = orig.Labels
			svc.Spec.Selector = orig.Spec.Selector
			svc.Spec.Type = orig.Spec.Type
			svc.Spec.Ports = orig.Spec.Ports

			return ctrl.SetControllerReference(lp.Object, svc, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	for _, v := range objs.ConfigMaps {
		if v == nil {
			continue
		}

		orig := v.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, v, func() error {
			v.Data = orig.Data

			return ctrl.SetControllerReference(lp.Object, v, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	if objs.CronJob != nil {
		orig := objs.CronJob.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, objs.CronJob, func() error {
			objs.CronJob.Spec = orig.Spec

			return ctrl.SetControllerReference(lp.Object, objs.CronJob, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	if objs.Certificate != nil {
		orig := objs.Certificate.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, objs.Certificate, func() error {
			objs.Certificate.Spec = orig.Spec

			return ctrl.SetControllerReference(lp.Object, objs.Certificate, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	for _, v := range objs.Secrets {
		if v == nil {
			continue
		}

		orig := v.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, v, func() error {
			v.Data = orig.Data

			return ctrl.SetControllerReference(lp.Object, v, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	if r.enablePrometheusOperator {
		for _, v := range objs.ServiceMonitors {
			if v == nil {
				continue
			}

			orig := v.DeepCopy()
			_, err := ctrl.CreateOrUpdate(context.Background(), r, v, func() error {
				v.Labels = orig.Labels
				v.Spec = orig.Spec

				return ctrl.SetControllerReference(lp.Object, v, r.Scheme)
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *ProxyReconciler) ReconcileMainProcess(lp *LagrangianProxy) error {
	secret := &corev1.Secret{}
	err := r.Get(context.Background(), client.ObjectKey{Name: lp.Spec.IdentityProvider.ClientSecretRef.Name, Namespace: lp.Namespace}, secret)
	if err != nil && apierrors.IsNotFound(err) {
		return err
	}

	objs, err := lp.Main()
	if err != nil {
		return err
	}

	return r.reconcileProcess(lp, objs)
}

func (r *ProxyReconciler) ReconcileDashboard(lp *LagrangianProxy) error {
	objs, err := lp.Dashboard()
	if err != nil {
		return err
	}

	return r.reconcileProcess(lp, objs)
}

func (r *ProxyReconciler) ReconcileRPCServer(lp *LagrangianProxy) error {
	objs, err := lp.RPCServer()
	if err != nil {
		return err
	}

	return r.reconcileProcess(lp, objs)
}

func (r *ProxyReconciler) preSetup(lp *LagrangianProxy) (bool, error) {
	requeue := false
	if err := r.ReconcileEtcdCluster(lp); err != nil {
		if err != ErrRetryReconcile {
			r.Log.Error(err, "Failed reconcile etcd cluster")
		}
		requeue = true
	}

	if requeue {
		return requeue, errors.New("controllers: pre setup is not completed")
	}

	if r.enableEtcdBackupOperator {
		if err := r.ReconcileEtcdBackup(lp); err != nil {
			return false, err
		}
	}

	return requeue, nil
}

func (r *ProxyReconciler) ReconcileEtcdCluster(lp *LagrangianProxy) error {
	cluster, porMonitor := lp.EtcdCluster()

	if porMonitor != nil && r.enablePrometheusOperator {
		orig := porMonitor.DeepCopy()
		_, err := ctrl.CreateOrUpdate(context.Background(), r, porMonitor, func() error {
			porMonitor.Labels = orig.Labels
			porMonitor.Spec = orig.Spec

			return ctrl.SetControllerReference(lp.Object, porMonitor, r.Scheme)
		})
		if err != nil {
			return err
		}
	}

	orig := cluster.DeepCopy()
	_, err := ctrl.CreateOrUpdate(context.Background(), r, cluster, func() error {
		cluster.Spec = orig.Spec

		return ctrl.SetControllerReference(lp.Object, cluster, r.Scheme)
	})
	if err != nil {
		return err
	}

	key, err := client.ObjectKeyFromObject(cluster)
	if err != nil {
		return err
	}
	if err := r.Get(context.Background(), key, cluster); err != nil {
		return err
	}

	for _, v := range cluster.Status.Conditions {
		if v.Status == corev1.ConditionTrue {
			return nil
		}
	}

	r.Log.Info("etcd cluster is not ready yet")
	return ErrRetryReconcile
}

func (r *ProxyReconciler) ReconcileEtcdBackup(lp *LagrangianProxy) error {
	backup := lp.EtcdBackup()

	orig := backup.DeepCopy()
	_, err := ctrl.CreateOrUpdate(context.Background(), r, backup, func() error {
		backup.Spec = orig.Spec

		return ctrl.SetControllerReference(lp.Object, backup, r.Scheme)
	})

	return err
}
