package controllers

import (
	"fmt"
	"sort"

	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	proxyv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha2"
)

type ConfigConverter struct {
}

func (ConfigConverter) Proxy(backends []*proxyv1alpha2.Backend, serviceLister listers.ServiceLister) ([]byte, error) {
	proxies := make([]*configv2.Backend, 0, len(backends))
	for _, v := range backends {
		_, virtualDashboard := v.Labels[labelKeyVirtualDashboard]

		name := v.Name + "." + v.Spec.Layer
		if v.Spec.Layer == "" {
			name = v.Name
		}

		routing := make([]*configv2.HTTPBackend, 0)
		for _, r := range v.Spec.HTTP {
			var service *corev1.Service
			if !virtualDashboard && r.Upstream == "" && r.ServiceSelector != nil {
				svc, err := findService(serviceLister, r.ServiceSelector, v.Namespace)
				if err != nil {
					// At this time, ignore error
					continue
				}
				if svc == nil {
					continue
				}
				service = svc
			}
			if r.Upstream == "" && service == nil && !r.Agent {
				continue
			}

			upstream := r.Upstream
			if upstream == "" && service != nil && !r.Agent {
				for _, p := range service.Spec.Ports {
					if p.Name == r.ServiceSelector.Port {
						scheme := r.ServiceSelector.Scheme
						if scheme == "" {
							switch p.Name {
							case "http", "https":
								scheme = p.Name
							}
						}

						upstream = fmt.Sprintf("%s://%s.%s.svc:%d", scheme, service.Name, service.Namespace, p.Port)
						break
					}
				}
			}

			routing = append(routing, &configv2.HTTPBackend{
				Path:     r.Path,
				Upstream: upstream,
				Insecure: r.Insecure,
				Agent:    r.Agent,
			})
		}

		var socket *configv2.SocketBackend
		if v.Spec.Socket != nil {
			upstream := v.Spec.Socket.Upstream
			if v.Spec.Socket.ServiceSelector != nil {
				svc, err := findService(serviceLister, v.Spec.Socket.ServiceSelector, v.Namespace)
				if err != nil {
					return nil, xerrors.Errorf(": %w", err)
				}
				for _, p := range svc.Spec.Ports {
					if p.Name == v.Spec.Socket.ServiceSelector.Port {
						upstream = fmt.Sprintf("tcp://%s.%s.svc:%d", svc.Name, svc.Namespace, p.Port)
						break
					}
				}
			}

			socket = &configv2.SocketBackend{
				Upstream: upstream,
				Agent:    v.Spec.Socket.Agent,
			}
			if v.Spec.Socket.Timeout != nil {
				socket.Timeout = &configv2.Duration{Duration: v.Spec.Socket.Timeout.Duration}
			}
		}

		b := &configv2.Backend{
			Name:          name,
			FQDN:          v.Spec.FQDN,
			HTTP:          routing,
			Socket:        socket,
			Permissions:   toConfigPermissions(v.Spec),
			AllowRootUser: v.Spec.AllowRootUser,
			DisableAuthn:  v.Spec.DisableAuthn,
			AllowHttp:     v.Spec.AllowHttp,
		}
		if v.Spec.MaxSessionDuration != nil {
			b.MaxSessionDuration = &configv2.Duration{Duration: v.Spec.MaxSessionDuration.Duration}
		}
		proxies = append(proxies, b)
	}
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].Name < proxies[j].Name
	})
	proxyBinary, err := yaml.Marshal(proxies)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return proxyBinary, nil
}

func (ConfigConverter) Role(backends []*proxyv1alpha2.Backend, roleList []*proxyv1alpha2.Role, roleBindings []*proxyv1alpha2.RoleBinding) ([]byte, error) {
	backendMap := make(map[string]*proxyv1alpha2.Backend)
	for _, v := range backends {
		backendMap[v.Namespace+"/"+v.Name] = v
	}

	roles := make([]*configv2.Role, len(roleList))
	for i, role := range roleList {
		bindings := make([]*configv2.Binding, 0)

		matchedBindings := RoleBindings(roleBindings).Select(func(binding *proxyv1alpha2.RoleBinding) bool {
			if binding.RoleRef.Name != role.Name {
				return false
			}
			if binding.RoleRef.Namespace != "" && binding.RoleRef.Namespace == role.Namespace {
				return true
			}
			if binding.RoleRef.Namespace == "" && binding.ObjectMeta.Namespace == role.Namespace {
				return true
			}

			return false
		})
		if role.Spec.AllowDashboard {
			matchedBindings = append(matchedBindings, &proxyv1alpha2.RoleBinding{
				Subjects: []proxyv1alpha2.Subject{
					{
						Kind:       "Backend",
						Name:       "dashboard",
						Permission: "all",
					},
				},
			})
		}

		sort.Slice(matchedBindings, func(i, j int) bool {
			return matchedBindings[i].Name < matchedBindings[j].Name
		})
		for _, binding := range matchedBindings {
			for _, subject := range binding.Subjects {
				switch subject.Kind {
				case "Backend":
					namespace := role.Namespace
					if subject.Namespace != "" {
						namespace = subject.Namespace
					}
					backendHost := ""
					if bn, ok := backendMap[namespace+"/"+subject.Name]; ok {
						backendHost = bn.Name + "." + bn.Spec.Layer
						if bn.Spec.Layer == "" {
							backendHost = bn.Name
						}
					} else {
						continue
					}

					bindings = append(bindings, &configv2.Binding{
						Permission: subject.Permission,
						Backend:    backendHost,
					})
				case "RpcPermission":
					bindings = append(bindings, &configv2.Binding{
						RPC: subject.Name,
					})
				}
			}
		}

		roles[i] = &configv2.Role{
			Name:        role.Name,
			Title:       role.Spec.Title,
			Description: role.Spec.Description,
			Bindings:    bindings,
		}
	}
	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Name < roles[j].Name
	})
	roleBinary, err := yaml.Marshal(roles)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return roleBinary, nil
}

func (ConfigConverter) RPCPermission(permissions []*proxyv1alpha2.RpcPermission) ([]byte, error) {
	rpcPermissions := make([]*configv2.RPCPermission, len(permissions))
	for i, v := range permissions {
		rpcPermissions[i] = &configv2.RPCPermission{
			Name:  v.Name,
			Allow: v.Spec.Allow,
		}
	}
	sort.Slice(rpcPermissions, func(i, j int) bool {
		return rpcPermissions[i].Name < rpcPermissions[j].Name
	})
	rpcPermissionBinary, err := yaml.Marshal(rpcPermissions)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return rpcPermissionBinary, nil
}
