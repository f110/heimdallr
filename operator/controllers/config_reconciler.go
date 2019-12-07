package controllers

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/api/v1"
	"github.com/f110/lagrangian-proxy/pkg/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/yaml"
)

const (
	ProxyFilename = "proxies.yaml"
	RoleFilename  = "roles.yaml"
)

func ConfigReconcile(c client.Client, scheme *runtime.Scheme, target *proxyv1.LagrangianProxy) error {
	selector, err := metav1.LabelSelectorAsSelector(&target.Spec.BackendSelector.LabelSelector)
	if err != nil {
		return err
	}
	backends := &proxyv1.BackendList{}
	if err := c.List(context.Background(), backends, &client.ListOptions{LabelSelector: selector, Namespace: target.Spec.BackendSelector.Namespace}); err != nil {
		return err
	}
	proxies := make([]*config.Backend, len(backends.Items))
	backendMap := make(map[string]*proxyv1.Backend)
	for i, v := range backends.Items {
		backendMap[v.Namespace+"/"+v.Name] = &v
		permissions := make([]*config.Permission, len(v.Spec.Permissions))
		for k, p := range v.Spec.Permissions {
			locations := make([]config.Location, len(p.Locations))
			for j, u := range p.Locations {
				locations[j] = config.Location{
					Any:     u.Any,
					Get:     u.Get,
					Post:    u.Post,
					Put:     u.Put,
					Delete:  u.Delete,
					Head:    u.Head,
					Connect: u.Connect,
					Options: u.Options,
					Trace:   u.Trace,
					Patch:   u.Patch,
				}
			}
			permissions[k] = &config.Permission{
				Name:      v.Spec.Permissions[k].Name,
				Locations: locations,
			}
		}
		proxies[i] = &config.Backend{
			Name:            v.Name + "." + target.Spec.Domain,
			Upstream:        v.Spec.Upstream,
			Permissions:     permissions,
			WebHook:         v.Spec.Webhook,
			WebHookPath:     v.Spec.WebhookPath,
			Agent:           v.Spec.Agent,
			AllowAsRootUser: v.Spec.AllowForRootUser,
		}
	}
	proxyBinary, err := yaml.Marshal(proxies)
	if err != nil {
		return err
	}

	selector, err = metav1.LabelSelectorAsSelector(&target.Spec.RoleSelector.LabelSelector)
	if err != nil {
		return err
	}
	roleList := &proxyv1.RoleList{}
	if err := c.List(context.Background(), roleList, &client.ListOptions{LabelSelector: selector, Namespace: target.Spec.RoleSelector.Namespace}); err != nil {
		return err
	}
	roles := make([]*config.Role, len(roleList.Items))
	for i, v := range roleList.Items {
		bindings := make([]config.Binding, len(v.Spec.Bindings))
		for k, b := range v.Spec.Bindings {
			namespace := v.Namespace
			if b.Namespace != "" {
				namespace = b.Namespace
			}
			backendHost := ""
			if bn, ok := backendMap[namespace+"/"+b.Name]; ok {
				backendHost = bn.Name + "." + target.Spec.Domain
			} else {
				return fmt.Errorf("controller: %s not found", b.Name)
			}

			bindings[k] = config.Binding{
				Permission: b.Permission,
				Backend:    backendHost,
			}
		}
		roles[i] = &config.Role{
			Name:        v.Name,
			Title:       v.Spec.Title,
			Description: v.Spec.Description,
			Bindings:    bindings,
		}
	}
	roleBinary, err := yaml.Marshal(roles)
	if err != nil {
		return err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      target.Name + "-hosts",
			Namespace: target.Namespace,
		},
		Data: make(map[string]string),
	}
	_, err = ctrl.CreateOrUpdate(context.Background(), c, configMap, func() error {
		configMap.Data[RoleFilename] = string(roleBinary)
		configMap.Data[ProxyFilename] = string(proxyBinary)

		return ctrl.SetControllerReference(target, configMap, scheme)
	})

	return nil
}
