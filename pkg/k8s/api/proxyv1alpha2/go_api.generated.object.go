package proxyv1alpha2

import (
	"github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const GroupName = "proxy.f110.dev"

var (
	GroupVersion       = metav1.GroupVersion{Group: GroupName, Version: "v1alpha1"}
	SchemeBuilder      = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme        = SchemeBuilder.AddToScheme
	SchemaGroupVersion = schema.GroupVersion{Group: "proxy.f110.dev", Version: "v1alpha1"}
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemaGroupVersion,
		&Backend{},
		&BackendList{},
		&Proxy{},
		&ProxyList{},
		&Role{},
		&RoleBinding{},
		&RoleBindingList{},
		&RoleList{},
		&RpcPermission{},
		&RpcPermissionList{},
	)
	metav1.AddToGroupVersion(scheme, SchemaGroupVersion)
	return nil
}

type ProxyPhase string

const (
	ProxyPhaseCreating ProxyPhase = "Creating"
	ProxyPhaseError    ProxyPhase = "Error"
	ProxyPhaseRunning  ProxyPhase = "Running"
	ProxyPhaseUpdating ProxyPhase = "Updating"
)

type Backend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              BackendSpec    `json:"spec"`
	Status            *BackendStatus `json:"status,omitempty"`
}

func (in *Backend) DeepCopyInto(out *Backend) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(BackendStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *Backend) DeepCopy() *Backend {
	if in == nil {
		return nil
	}
	out := new(Backend)
	in.DeepCopyInto(out)
	return out
}

func (in *Backend) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Backend `json:"items"`
}

func (in *BackendList) DeepCopyInto(out *BackendList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Backend, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *BackendList) DeepCopy() *BackendList {
	if in == nil {
		return nil
	}
	out := new(BackendList)
	in.DeepCopyInto(out)
	return out
}

func (in *BackendList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type Proxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              ProxySpec    `json:"spec"`
	Status            *ProxyStatus `json:"status,omitempty"`
}

func (in *Proxy) DeepCopyInto(out *Proxy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(ProxyStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *Proxy) DeepCopy() *Proxy {
	if in == nil {
		return nil
	}
	out := new(Proxy)
	in.DeepCopyInto(out)
	return out
}

func (in *Proxy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Proxy `json:"items"`
}

func (in *ProxyList) DeepCopyInto(out *ProxyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Proxy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *ProxyList) DeepCopy() *ProxyList {
	if in == nil {
		return nil
	}
	out := new(ProxyList)
	in.DeepCopyInto(out)
	return out
}

func (in *ProxyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              RoleSpec   `json:"spec"`
	Status            RoleStatus `json:"status"`
}

func (in *Role) DeepCopyInto(out *Role) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *Role) DeepCopy() *Role {
	if in == nil {
		return nil
	}
	out := new(Role)
	in.DeepCopyInto(out)
	return out
}

func (in *Role) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type RoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Subjects          []Subject `json:"subjects"`
	RoleRef           RoleRef   `json:"roleRef"`
}

func (in *RoleBinding) DeepCopyInto(out *RoleBinding) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Subjects != nil {
		l := make([]Subject, len(in.Subjects))
		for i := range in.Subjects {
			in.Subjects[i].DeepCopyInto(&l[i])
		}
		out.Subjects = l
	}
	in.RoleRef.DeepCopyInto(&out.RoleRef)
}

func (in *RoleBinding) DeepCopy() *RoleBinding {
	if in == nil {
		return nil
	}
	out := new(RoleBinding)
	in.DeepCopyInto(out)
	return out
}

func (in *RoleBinding) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type RoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []RoleBinding `json:"items"`
}

func (in *RoleBindingList) DeepCopyInto(out *RoleBindingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]RoleBinding, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *RoleBindingList) DeepCopy() *RoleBindingList {
	if in == nil {
		return nil
	}
	out := new(RoleBindingList)
	in.DeepCopyInto(out)
	return out
}

func (in *RoleBindingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Role `json:"items"`
}

func (in *RoleList) DeepCopyInto(out *RoleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Role, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *RoleList) DeepCopy() *RoleList {
	if in == nil {
		return nil
	}
	out := new(RoleList)
	in.DeepCopyInto(out)
	return out
}

func (in *RoleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type RpcPermission struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
}

func (in *RpcPermission) DeepCopyInto(out *RpcPermission) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
}

func (in *RpcPermission) DeepCopy() *RpcPermission {
	if in == nil {
		return nil
	}
	out := new(RpcPermission)
	in.DeepCopyInto(out)
	return out
}

func (in *RpcPermission) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type RpcPermissionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []RpcPermission `json:"items"`
}

func (in *RpcPermissionList) DeepCopyInto(out *RpcPermissionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]RpcPermission, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *RpcPermissionList) DeepCopy() *RpcPermissionList {
	if in == nil {
		return nil
	}
	out := new(RpcPermissionList)
	in.DeepCopyInto(out)
	return out
}

func (in *RpcPermissionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type BackendSpec struct {
	FQDN               string             `json:"fqdn,omitempty"`
	Layer              string             `json:"layer,omitempty"`
	AllowRootUser      bool               `json:"allowRootUser,omitempty"`
	DisableAuthn       bool               `json:"disableAuthn,omitempty"`
	AllowHttp          bool               `json:"allowHttp,omitempty"`
	Permissions        []Permission       `json:"permissions"`
	MaxSessionDuration *metav1.Duration   `json:"maxSessionDuration,omitempty"`
	HTTP               []BackendHTTPSpec  `json:"http"`
	Socket             *BackendSocketSpec `json:"socket,omitempty"`
}

func (in *BackendSpec) DeepCopyInto(out *BackendSpec) {
	*out = *in
	if in.Permissions != nil {
		l := make([]Permission, len(in.Permissions))
		for i := range in.Permissions {
			in.Permissions[i].DeepCopyInto(&l[i])
		}
		out.Permissions = l
	}
	if in.MaxSessionDuration != nil {
		in, out := &in.MaxSessionDuration, &out.MaxSessionDuration
		*out = new(metav1.Duration)
		(*in).DeepCopyInto(*out)
	}
	if in.HTTP != nil {
		l := make([]BackendHTTPSpec, len(in.HTTP))
		for i := range in.HTTP {
			in.HTTP[i].DeepCopyInto(&l[i])
		}
		out.HTTP = l
	}
	if in.Socket != nil {
		in, out := &in.Socket, &out.Socket
		*out = new(BackendSocketSpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BackendSpec) DeepCopy() *BackendSpec {
	if in == nil {
		return nil
	}
	out := new(BackendSpec)
	in.DeepCopyInto(out)
	return out
}

type BackendStatus struct {
	DeployedBy            []ProxyReference             `json:"deployedBy"`
	WebhookConfigurations []WebhookConfigurationStatus `json:"webhookConfigurations"`
}

func (in *BackendStatus) DeepCopyInto(out *BackendStatus) {
	*out = *in
	if in.DeployedBy != nil {
		l := make([]ProxyReference, len(in.DeployedBy))
		for i := range in.DeployedBy {
			in.DeployedBy[i].DeepCopyInto(&l[i])
		}
		out.DeployedBy = l
	}
	if in.WebhookConfigurations != nil {
		l := make([]WebhookConfigurationStatus, len(in.WebhookConfigurations))
		for i := range in.WebhookConfigurations {
			in.WebhookConfigurations[i].DeepCopyInto(&l[i])
		}
		out.WebhookConfigurations = l
	}
}

func (in *BackendStatus) DeepCopy() *BackendStatus {
	if in == nil {
		return nil
	}
	out := new(BackendStatus)
	in.DeepCopyInto(out)
	return out
}

type ProxySpec struct {
	Domain                string                       `json:"domain"`
	Port                  int                          `json:"port,omitempty"`
	HttpPort              int                          `json:"httpPort,omitempty"`
	Version               string                       `json:"version,omitempty"`
	DataStore             *ProxyDataStoreSpec          `json:"dataStore,omitempty"`
	LoadBalancerIP        string                       `json:"loadBalancerIp,omitempty"`
	CertificateAuthority  *CertificateAuthoritySpec    `json:"certificateAuthority,omitempty"`
	IssuerRef             v1.ObjectReference           `json:"issuerRef"`
	IdentityProvider      IdentityProviderSpec         `json:"identityProvider"`
	RootUsers             []string                     `json:"rootUsers"`
	Session               SessionSpec                  `json:"session"`
	Replicas              int                          `json:"replicas"`
	RPCReplicas           int                          `json:"rpcReplicas,omitempty"`
	DashboardReplicas     int                          `json:"dashboardReplicas,omitempty"`
	BackendSelector       *LabelSelector               `json:"backendSelector,omitempty"`
	RoleSelector          *LabelSelector               `json:"roleSelector,omitempty"`
	RpcPermissionSelector *LabelSelector               `json:"rpcPermissionSelector,omitempty"`
	AntiAffinity          bool                         `json:"antiAffinity,omitempty"`
	Monitor               *MonitorSpec                 `json:"monitor,omitempty"`
	Backup                *BackupSpec                  `json:"backup,omitempty"`
	ProxyResources        *corev1.ResourceRequirements `json:"proxyResources,omitempty"`
	RPCServerResources    *corev1.ResourceRequirements `json:"rpcServerResources,omitempty"`
	Development           bool                         `json:"development,omitempty"`
}

func (in *ProxySpec) DeepCopyInto(out *ProxySpec) {
	*out = *in
	if in.DataStore != nil {
		in, out := &in.DataStore, &out.DataStore
		*out = new(ProxyDataStoreSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.CertificateAuthority != nil {
		in, out := &in.CertificateAuthority, &out.CertificateAuthority
		*out = new(CertificateAuthoritySpec)
		(*in).DeepCopyInto(*out)
	}
	in.IssuerRef.DeepCopyInto(&out.IssuerRef)
	in.IdentityProvider.DeepCopyInto(&out.IdentityProvider)
	if in.RootUsers != nil {
		t := make([]string, len(in.RootUsers))
		copy(t, in.RootUsers)
		out.RootUsers = t
	}
	in.Session.DeepCopyInto(&out.Session)
	if in.BackendSelector != nil {
		in, out := &in.BackendSelector, &out.BackendSelector
		*out = new(LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.RoleSelector != nil {
		in, out := &in.RoleSelector, &out.RoleSelector
		*out = new(LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.RpcPermissionSelector != nil {
		in, out := &in.RpcPermissionSelector, &out.RpcPermissionSelector
		*out = new(LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Monitor != nil {
		in, out := &in.Monitor, &out.Monitor
		*out = new(MonitorSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Backup != nil {
		in, out := &in.Backup, &out.Backup
		*out = new(BackupSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.ProxyResources != nil {
		in, out := &in.ProxyResources, &out.ProxyResources
		*out = new(corev1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	if in.RPCServerResources != nil {
		in, out := &in.RPCServerResources, &out.RPCServerResources
		*out = new(corev1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ProxySpec) DeepCopy() *ProxySpec {
	if in == nil {
		return nil
	}
	out := new(ProxySpec)
	in.DeepCopyInto(out)
	return out
}

type ProxyStatus struct {
	Ready                       bool       `json:"ready"`
	Phase                       ProxyPhase `json:"phase,omitempty"`
	NumOfBackends               int        `json:"numberOfBackends,omitempty"`
	NumOfRoles                  int        `json:"numberOfRoles,omitempty"`
	NumOfRpcPermissions         int        `json:"numberOfRpcPermissions,omitempty"`
	CASecretName                string     `json:"caSecretName,omitempty"`
	SigningPrivateKeySecretName string     `json:"signingPrivateKeySecretName,omitempty"`
	GithubWebhookSecretName     string     `json:"githubWebhookSecretName,omitempty"`
	CookieSecretName            string     `json:"cookieSecretName,omitempty"`
	InternalTokenSecretName     string     `json:"internalTokenSecretName,omitempty"`
}

func (in *ProxyStatus) DeepCopyInto(out *ProxyStatus) {
	*out = *in
}

func (in *ProxyStatus) DeepCopy() *ProxyStatus {
	if in == nil {
		return nil
	}
	out := new(ProxyStatus)
	in.DeepCopyInto(out)
	return out
}

type RoleSpec struct {
	Title          string `json:"title,omitempty"`
	Description    string `json:"description,omitempty"`
	AllowDashboard bool   `json:"allowDashboard,omitempty"`
}

func (in *RoleSpec) DeepCopyInto(out *RoleSpec) {
	*out = *in
}

func (in *RoleSpec) DeepCopy() *RoleSpec {
	if in == nil {
		return nil
	}
	out := new(RoleSpec)
	in.DeepCopyInto(out)
	return out
}

type RoleStatus struct {
	Spec   RpcPermissionSpec   `json:"spec"`
	Status RpcPermissionStatus `json:"status"`
}

func (in *RoleStatus) DeepCopyInto(out *RoleStatus) {
	*out = *in
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *RoleStatus) DeepCopy() *RoleStatus {
	if in == nil {
		return nil
	}
	out := new(RoleStatus)
	in.DeepCopyInto(out)
	return out
}

type Subject struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
	Permission string `json:"permission,omitempty"`
}

func (in *Subject) DeepCopyInto(out *Subject) {
	*out = *in
}

func (in *Subject) DeepCopy() *Subject {
	if in == nil {
		return nil
	}
	out := new(Subject)
	in.DeepCopyInto(out)
	return out
}

type RoleRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func (in *RoleRef) DeepCopyInto(out *RoleRef) {
	*out = *in
}

func (in *RoleRef) DeepCopy() *RoleRef {
	if in == nil {
		return nil
	}
	out := new(RoleRef)
	in.DeepCopyInto(out)
	return out
}

type Permission struct {
	Name      string     `json:"name,omitempty"`
	Locations []Location `json:"locations"`
}

func (in *Permission) DeepCopyInto(out *Permission) {
	*out = *in
	if in.Locations != nil {
		l := make([]Location, len(in.Locations))
		for i := range in.Locations {
			in.Locations[i].DeepCopyInto(&l[i])
		}
		out.Locations = l
	}
}

func (in *Permission) DeepCopy() *Permission {
	if in == nil {
		return nil
	}
	out := new(Permission)
	in.DeepCopyInto(out)
	return out
}

type BackendHTTPSpec struct {
	Path            string           `json:"path"`
	ServiceSelector *ServiceSelector `json:"serviceSelector,omitempty"`
	Upstream        string           `json:"upstream,omitempty"`
	Insecure        bool             `json:"insecure,omitempty"`
	Agent           bool             `json:"agent,omitempty"`
}

func (in *BackendHTTPSpec) DeepCopyInto(out *BackendHTTPSpec) {
	*out = *in
	if in.ServiceSelector != nil {
		in, out := &in.ServiceSelector, &out.ServiceSelector
		*out = new(ServiceSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BackendHTTPSpec) DeepCopy() *BackendHTTPSpec {
	if in == nil {
		return nil
	}
	out := new(BackendHTTPSpec)
	in.DeepCopyInto(out)
	return out
}

type BackendSocketSpec struct {
	Upstream        string           `json:"upstream,omitempty"`
	ServiceSelector *ServiceSelector `json:"serviceSelector,omitempty"`
	Timeout         *metav1.Duration `json:"timeout,omitempty"`
	Agent           bool             `json:"agent,omitempty"`
}

func (in *BackendSocketSpec) DeepCopyInto(out *BackendSocketSpec) {
	*out = *in
	if in.ServiceSelector != nil {
		in, out := &in.ServiceSelector, &out.ServiceSelector
		*out = new(ServiceSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Timeout != nil {
		in, out := &in.Timeout, &out.Timeout
		*out = new(metav1.Duration)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BackendSocketSpec) DeepCopy() *BackendSocketSpec {
	if in == nil {
		return nil
	}
	out := new(BackendSocketSpec)
	in.DeepCopyInto(out)
	return out
}

type ProxyReference struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Url       string `json:"url,omitempty"`
}

func (in *ProxyReference) DeepCopyInto(out *ProxyReference) {
	*out = *in
}

func (in *ProxyReference) DeepCopy() *ProxyReference {
	if in == nil {
		return nil
	}
	out := new(ProxyReference)
	in.DeepCopyInto(out)
	return out
}

type WebhookConfigurationStatus struct {
	Id         int64        `json:"id"`
	Repository string       `json:"repository,omitempty"`
	UpdateTime *metav1.Time `json:"updateTime,omitempty"`
}

func (in *WebhookConfigurationStatus) DeepCopyInto(out *WebhookConfigurationStatus) {
	*out = *in
	if in.UpdateTime != nil {
		in, out := &in.UpdateTime, &out.UpdateTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *WebhookConfigurationStatus) DeepCopy() *WebhookConfigurationStatus {
	if in == nil {
		return nil
	}
	out := new(WebhookConfigurationStatus)
	in.DeepCopyInto(out)
	return out
}

type ProxyDataStoreSpec struct {
	Etcd *ProxyDataStoreEtcdSpec `json:"etcd,omitempty"`
}

func (in *ProxyDataStoreSpec) DeepCopyInto(out *ProxyDataStoreSpec) {
	*out = *in
	if in.Etcd != nil {
		in, out := &in.Etcd, &out.Etcd
		*out = new(ProxyDataStoreEtcdSpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ProxyDataStoreSpec) DeepCopy() *ProxyDataStoreSpec {
	if in == nil {
		return nil
	}
	out := new(ProxyDataStoreSpec)
	in.DeepCopyInto(out)
	return out
}

type CertificateAuthoritySpec struct {
	Local *LocalCertificateAuthoritySpec `json:"local,omitempty"`
	Vault *VaultCertificateAuthoritySpec `json:"vault,omitempty"`
}

func (in *CertificateAuthoritySpec) DeepCopyInto(out *CertificateAuthoritySpec) {
	*out = *in
	if in.Local != nil {
		in, out := &in.Local, &out.Local
		*out = new(LocalCertificateAuthoritySpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Vault != nil {
		in, out := &in.Vault, &out.Vault
		*out = new(VaultCertificateAuthoritySpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CertificateAuthoritySpec) DeepCopy() *CertificateAuthoritySpec {
	if in == nil {
		return nil
	}
	out := new(CertificateAuthoritySpec)
	in.DeepCopyInto(out)
	return out
}

type IdentityProviderSpec struct {
	Provider        string          `json:"provider"`
	ClientId        string          `json:"clientId,omitempty"`
	ClientSecretRef *SecretSelector `json:"clientSecretRef,omitempty"`
	RedirectUrl     string          `json:"redirectUrl,omitempty"`
}

func (in *IdentityProviderSpec) DeepCopyInto(out *IdentityProviderSpec) {
	*out = *in
	if in.ClientSecretRef != nil {
		in, out := &in.ClientSecretRef, &out.ClientSecretRef
		*out = new(SecretSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *IdentityProviderSpec) DeepCopy() *IdentityProviderSpec {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderSpec)
	in.DeepCopyInto(out)
	return out
}

type SessionSpec struct {
	Type         string          `json:"type"`
	KeySecretRef *SecretSelector `json:"keySecretRef,omitempty"`
}

func (in *SessionSpec) DeepCopyInto(out *SessionSpec) {
	*out = *in
	if in.KeySecretRef != nil {
		in, out := &in.KeySecretRef, &out.KeySecretRef
		*out = new(SecretSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *SessionSpec) DeepCopy() *SessionSpec {
	if in == nil {
		return nil
	}
	out := new(SessionSpec)
	in.DeepCopyInto(out)
	return out
}

type LabelSelector struct {
	LabelSelector metav1.LabelSelector `json:",inline"`
	Namespace     string               `json:"namespace,omitempty"`
}

func (in *LabelSelector) DeepCopyInto(out *LabelSelector) {
	*out = *in
	out.LabelSelector = in.LabelSelector
}

func (in *LabelSelector) DeepCopy() *LabelSelector {
	if in == nil {
		return nil
	}
	out := new(LabelSelector)
	in.DeepCopyInto(out)
	return out
}

type MonitorSpec struct {
	PrometheusMonitoring bool              `json:"prometheusMonitoring,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`
}

func (in *MonitorSpec) DeepCopyInto(out *MonitorSpec) {
	*out = *in
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
}

func (in *MonitorSpec) DeepCopy() *MonitorSpec {
	if in == nil {
		return nil
	}
	out := new(MonitorSpec)
	in.DeepCopyInto(out)
	return out
}

type BackupSpec struct {
	IntervalInSecond int64          `json:"intervalInSecond"`
	MaxBackups       int            `json:"maxBackups,omitempty"`
	Bucket           string         `json:"bucket"`
	Path             string         `json:"path"`
	CredentialRef    SecretSelector `json:"credentialRef"`
	Endpoint         string         `json:"endpoint,omitempty"`
}

func (in *BackupSpec) DeepCopyInto(out *BackupSpec) {
	*out = *in
	in.CredentialRef.DeepCopyInto(&out.CredentialRef)
}

func (in *BackupSpec) DeepCopy() *BackupSpec {
	if in == nil {
		return nil
	}
	out := new(BackupSpec)
	in.DeepCopyInto(out)
	return out
}

type RpcPermissionSpec struct {
	Allow []string `json:"allow"`
}

func (in *RpcPermissionSpec) DeepCopyInto(out *RpcPermissionSpec) {
	*out = *in
	if in.Allow != nil {
		t := make([]string, len(in.Allow))
		copy(t, in.Allow)
		out.Allow = t
	}
}

func (in *RpcPermissionSpec) DeepCopy() *RpcPermissionSpec {
	if in == nil {
		return nil
	}
	out := new(RpcPermissionSpec)
	in.DeepCopyInto(out)
	return out
}

type RpcPermissionStatus struct {
}

func (in *RpcPermissionStatus) DeepCopyInto(out *RpcPermissionStatus) {
	*out = *in
}

func (in *RpcPermissionStatus) DeepCopy() *RpcPermissionStatus {
	if in == nil {
		return nil
	}
	out := new(RpcPermissionStatus)
	in.DeepCopyInto(out)
	return out
}

type Location struct {
	Any     string `json:"any,omitempty"`
	Get     string `json:"get,omitempty"`
	Post    string `json:"post,omitempty"`
	Put     string `json:"put,omitempty"`
	Delete  string `json:"delete,omitempty"`
	Head    string `json:"head,omitempty"`
	Connect string `json:"connect,omitempty"`
	Options string `json:"options,omitempty"`
	Trace   string `json:"trace,omitempty"`
	Patch   string `json:"patch,omitempty"`
}

func (in *Location) DeepCopyInto(out *Location) {
	*out = *in
}

func (in *Location) DeepCopy() *Location {
	if in == nil {
		return nil
	}
	out := new(Location)
	in.DeepCopyInto(out)
	return out
}

type ServiceSelector struct {
	LabelSelector metav1.LabelSelector `json:",inline"`
	Namespace     string               `json:"namespace,omitempty"`
	Name          string               `json:"name,omitempty"`
	Port          string               `json:"port,omitempty"`
	Scheme        string               `json:"scheme,omitempty"`
}

func (in *ServiceSelector) DeepCopyInto(out *ServiceSelector) {
	*out = *in
	out.LabelSelector = in.LabelSelector
}

func (in *ServiceSelector) DeepCopy() *ServiceSelector {
	if in == nil {
		return nil
	}
	out := new(ServiceSelector)
	in.DeepCopyInto(out)
	return out
}

type ProxyDataStoreEtcdSpec struct {
	Version      string          `json:"version,omitempty"`
	Defragment   *DefragmentSpec `json:"defragment,omitempty"`
	AntiAffinity bool            `json:"antiAffinity,omitempty"`
	Backup       *EtcdBackupSpec `json:"backup,omitempty"`
}

func (in *ProxyDataStoreEtcdSpec) DeepCopyInto(out *ProxyDataStoreEtcdSpec) {
	*out = *in
	if in.Defragment != nil {
		in, out := &in.Defragment, &out.Defragment
		*out = new(DefragmentSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Backup != nil {
		in, out := &in.Backup, &out.Backup
		*out = new(EtcdBackupSpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ProxyDataStoreEtcdSpec) DeepCopy() *ProxyDataStoreEtcdSpec {
	if in == nil {
		return nil
	}
	out := new(ProxyDataStoreEtcdSpec)
	in.DeepCopyInto(out)
	return out
}

type LocalCertificateAuthoritySpec struct {
	Name              string `json:"name,omitempty"`
	Organization      string `json:"organization,omitempty"`
	AdministratorUnit string `json:"administratorUnit,omitempty"`
	Country           string `json:"country,omitempty"`
}

func (in *LocalCertificateAuthoritySpec) DeepCopyInto(out *LocalCertificateAuthoritySpec) {
	*out = *in
}

func (in *LocalCertificateAuthoritySpec) DeepCopy() *LocalCertificateAuthoritySpec {
	if in == nil {
		return nil
	}
	out := new(LocalCertificateAuthoritySpec)
	in.DeepCopyInto(out)
	return out
}

type VaultCertificateAuthoritySpec struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
	Role  string `json:"role"`
}

func (in *VaultCertificateAuthoritySpec) DeepCopyInto(out *VaultCertificateAuthoritySpec) {
	*out = *in
}

func (in *VaultCertificateAuthoritySpec) DeepCopy() *VaultCertificateAuthoritySpec {
	if in == nil {
		return nil
	}
	out := new(VaultCertificateAuthoritySpec)
	in.DeepCopyInto(out)
	return out
}

type SecretSelector struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

func (in *SecretSelector) DeepCopyInto(out *SecretSelector) {
	*out = *in
}

func (in *SecretSelector) DeepCopy() *SecretSelector {
	if in == nil {
		return nil
	}
	out := new(SecretSelector)
	in.DeepCopyInto(out)
	return out
}

type LabelsEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (in *LabelsEntry) DeepCopyInto(out *LabelsEntry) {
	*out = *in
}

func (in *LabelsEntry) DeepCopy() *LabelsEntry {
	if in == nil {
		return nil
	}
	out := new(LabelsEntry)
	in.DeepCopyInto(out)
	return out
}

type DefragmentSpec struct {
	Schedule string `json:"schedule,omitempty"`
}

func (in *DefragmentSpec) DeepCopyInto(out *DefragmentSpec) {
	*out = *in
}

func (in *DefragmentSpec) DeepCopy() *DefragmentSpec {
	if in == nil {
		return nil
	}
	out := new(DefragmentSpec)
	in.DeepCopyInto(out)
	return out
}

type EtcdBackupSpec struct {
	IntervalInSecond int                    `json:"intervalInSecond,omitempty"`
	MaxBackups       int                    `json:"maxBackups,omitempty"`
	Storage          *EtcdBackupStorageSpec `json:"storage,omitempty"`
}

func (in *EtcdBackupSpec) DeepCopyInto(out *EtcdBackupSpec) {
	*out = *in
	if in.Storage != nil {
		in, out := &in.Storage, &out.Storage
		*out = new(EtcdBackupStorageSpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *EtcdBackupSpec) DeepCopy() *EtcdBackupSpec {
	if in == nil {
		return nil
	}
	out := new(EtcdBackupSpec)
	in.DeepCopyInto(out)
	return out
}

type EtcdBackupStorageSpec struct {
	MinIO *EtcdBackupMinIOSpec `json:"minio,omitempty"`
	GCS   *EtcdBackupGCSSpec   `json:"gcs,omitempty"`
}

func (in *EtcdBackupStorageSpec) DeepCopyInto(out *EtcdBackupStorageSpec) {
	*out = *in
	if in.MinIO != nil {
		in, out := &in.MinIO, &out.MinIO
		*out = new(EtcdBackupMinIOSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.GCS != nil {
		in, out := &in.GCS, &out.GCS
		*out = new(EtcdBackupGCSSpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *EtcdBackupStorageSpec) DeepCopy() *EtcdBackupStorageSpec {
	if in == nil {
		return nil
	}
	out := new(EtcdBackupStorageSpec)
	in.DeepCopyInto(out)
	return out
}

type EtcdBackupMinIOSpec struct {
	ServiceSelector    *ObjectSelector        `json:"serviceSelector,omitempty"`
	CredentialSelector *AWSCredentialSelector `json:"credentialSelector,omitempty"`
	Bucket             string                 `json:"bucket,omitempty"`
	Path               string                 `json:"path,omitempty"`
	Secure             bool                   `json:"secure,omitempty"`
}

func (in *EtcdBackupMinIOSpec) DeepCopyInto(out *EtcdBackupMinIOSpec) {
	*out = *in
	if in.ServiceSelector != nil {
		in, out := &in.ServiceSelector, &out.ServiceSelector
		*out = new(ObjectSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.CredentialSelector != nil {
		in, out := &in.CredentialSelector, &out.CredentialSelector
		*out = new(AWSCredentialSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *EtcdBackupMinIOSpec) DeepCopy() *EtcdBackupMinIOSpec {
	if in == nil {
		return nil
	}
	out := new(EtcdBackupMinIOSpec)
	in.DeepCopyInto(out)
	return out
}

type EtcdBackupGCSSpec struct {
	Bucket             string                 `json:"bucket,omitempty"`
	Path               string                 `json:"path,omitempty"`
	CredentialSelector *GCPCredentialSelector `json:"credentialSelector,omitempty"`
}

func (in *EtcdBackupGCSSpec) DeepCopyInto(out *EtcdBackupGCSSpec) {
	*out = *in
	if in.CredentialSelector != nil {
		in, out := &in.CredentialSelector, &out.CredentialSelector
		*out = new(GCPCredentialSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *EtcdBackupGCSSpec) DeepCopy() *EtcdBackupGCSSpec {
	if in == nil {
		return nil
	}
	out := new(EtcdBackupGCSSpec)
	in.DeepCopyInto(out)
	return out
}

type ObjectSelector struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

func (in *ObjectSelector) DeepCopyInto(out *ObjectSelector) {
	*out = *in
}

func (in *ObjectSelector) DeepCopy() *ObjectSelector {
	if in == nil {
		return nil
	}
	out := new(ObjectSelector)
	in.DeepCopyInto(out)
	return out
}

type AWSCredentialSelector struct {
	Name               string `json:"name,omitempty"`
	Namespace          string `json:"namespace,omitempty"`
	AccessKeyIDKey     string `json:"accessKeyIdKey,omitempty"`
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`
}

func (in *AWSCredentialSelector) DeepCopyInto(out *AWSCredentialSelector) {
	*out = *in
}

func (in *AWSCredentialSelector) DeepCopy() *AWSCredentialSelector {
	if in == nil {
		return nil
	}
	out := new(AWSCredentialSelector)
	in.DeepCopyInto(out)
	return out
}

type GCPCredentialSelector struct {
	Name                  string `json:"name,omitempty"`
	Namespace             string `json:"namespace,omitempty"`
	ServiceAccountJSONKey string `json:"serviceAccountJsonKey,omitempty"`
}

func (in *GCPCredentialSelector) DeepCopyInto(out *GCPCredentialSelector) {
	*out = *in
}

func (in *GCPCredentialSelector) DeepCopy() *GCPCredentialSelector {
	if in == nil {
		return nil
	}
	out := new(GCPCredentialSelector)
	in.DeepCopyInto(out)
	return out
}
