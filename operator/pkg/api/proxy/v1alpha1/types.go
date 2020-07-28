package v1alpha1

import (
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type SecretSelector struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

type LabelSelector struct {
	metav1.LabelSelector `json:",inline"`
	Namespace            string `json:"namespace,omitempty"`
}

// ProxySpec defines the desired state of Proxy
type ProxySpec struct {
	Domain         string `json:"domain"`
	Port           int32  `json:"port,omitempty"`
	HttpPort       int32  `json:"httpPort,omitempty"`
	Version        string `json:"version,omitempty"`
	EtcdVersion    string `json:"etcdVersion,omitempty"`
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`
	// Name of proxy. if not present, uses "Heimdallr CA".
	Name              string                 `json:"name,omitempty"`
	Organization      string                 `json:"organization"`
	AdministratorUnit string                 `json:"administratorUnit"`
	Country           string                 `json:"country,omitempty"`
	IssuerRef         cmmeta.ObjectReference `json:"issuerRef"`
	IdentityProvider  IdentityProviderSpec   `json:"identityProvider"`
	RootUsers         []string               `json:"rootUsers,omitempty"`
	Session           SessionSpec            `json:"session"`
	// The number of replicas of front proxy.
	Replicas int32 `json:"replicas"`
	// The number of replicas of dashboard. Default value is "3".
	DashboardReplicas     int32          `json:"dashboardReplicas,omitempty"`
	BackendSelector       LabelSelector  `json:"backendSelector,omitempty"`
	RoleSelector          LabelSelector  `json:"roleSelector,omitempty"`
	RpcPermissionSelector LabelSelector  `json:"rpcPermissionSelector,omitempty"`
	Defragment            DefragmentSpec `json:"defragment,omitempty"`
	Monitor               MonitorSpec    `json:"monitor,omitempty"`
	Backup                BackupSpec     `json:"backup,omitempty"`
	// ProxyResources field is able to control the resource requirements and limits of front proxy.
	// If it isn't set, Use the default value.
	// (Default Value: requirements is cpu: 100m and memory: 128Mi. limits is cpu: 1 and memory: 256Mi)
	ProxyResources *corev1.ResourceRequirements `json:"proxyResources,omitempty"`
	// RPCServerResources field is able tot control the resource requirements and limits of rpc server.
	// If it isn't set, Use the default value.
	// (Default Value: requirements is cpu: 100m and memory: 128Mi. limits is cpu: 1 and memory 256Mi)
	RPCServerResources *corev1.ResourceRequirements `json:"rpcServerResources,omitempty"`
	// Development indicates the development mode. If the proxy deployed with the development mode,
	// then the log level of logger will be "Debug".
	// Debug level outputs many useful logs for development. On the other hand, It is a noisy
	// when you are an user of proxy.
	Development bool `json:"development,omitempty"`
}

type IdentityProviderSpec struct {
	Provider        string         `json:"provider"`
	ClientId        string         `json:"clientId,omitempty"`
	ClientSecretRef SecretSelector `json:"clientSecretRef,omitempty"`
	RedirectUrl     string         `json:"redirectUrl,omitempty"`
}

type SessionSpec struct {
	Type         string         `json:"type"`
	KeySecretRef SecretSelector `json:"keySecretRef,omitempty"`
}

type DefragmentSpec struct {
	Schedule string `json:"schedule,omitempty"`
}

type MonitorSpec struct {
	// PrometheusMonitoring is set to true, then operator creates ServiceMonitor object.
	PrometheusMonitoring bool              `json:"prometheusMonitoring,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`
}

type BackupSpec struct {
	IntervalInSecond int64          `json:"intervalInSecond"`
	MaxBackups       int            `json:"maxBackups,omitempty"`
	Bucket           string         `json:"bucket"`
	Path             string         `json:"path"`
	CredentialRef    SecretSelector `json:"credentialRef"`
	Endpoint         string         `json:"endpoint,omitempty"`
}

type ProxyPhase string

var (
	ProxyPhaseCreating ProxyPhase = "Creating"
	ProxyPhaseRunning  ProxyPhase = "Running"
	ProxyPhaseUpdating ProxyPhase = "Updating"
)

// ProxyStatus defines the observed state of Proxy
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

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ready",type="string",JSONPath=".status.ready",description="Ready",format="byte",priority=0
// +kubebuilder:printcolumn:name="phase",type="string",JSONPath=".status.phase",description="Phase",format="byte",priority=0
// +kubebuilder:printcolumn:name="backends",type="string",JSONPath=".status.numberOfBackends",description="Backends",format="byte",priority=0
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp",description="Age",format="date",priority=0

// Proxy is the Schema for the proxies API
type Proxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProxySpec   `json:"spec,omitempty"`
	Status ProxyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProxyList contains a list of Proxy
type ProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Proxy `json:"items"`
}

type ServiceSelector struct {
	metav1.LabelSelector `json:",inline"`
	Namespace            string `json:"namespace,omitempty"`
	Port                 string `json:"port,omitempty"`
	Scheme               string `json:"scheme,omitempty"`
}

// BackendSpec defines the desired state of Backend
type BackendSpec struct {
	FQDN                 string                `json:"fqdn,omitempty"` // If fqdn is set, ignore a layer-style naming.
	Layer                string                `json:"layer,omitempty"`
	Upstream             string                `json:"upstream,omitempty"`
	SocketTimeout        *metav1.Duration      `json:"socketTimeout,omitempty"`
	ServiceSelector      ServiceSelector       `json:"serviceSelector,omitempty"`
	Webhook              string                `json:"webhook,omitempty"`
	WebhookPath          []string              `json:"webhookPath,omitempty"`
	AllowRootUser        bool                  `json:"allowRootUser,omitempty"`
	Agent                bool                  `json:"agent,omitempty"`
	Socket               bool                  `json:"socket,omitempty"`
	DisableAuthn         bool                  `json:"disableAuthn,omitempty"`
	Insecure             bool                  `json:"insecure,omitempty"`
	AllowHttp            bool                  `json:"allowHttp,omitempty"`
	Permissions          []Permission          `json:"permissions,omitempty"`
	WebhookConfiguration *WebhookConfiguration `json:"webhookConfiguration,omitempty"`
}

type WebhookConfiguration struct {
	GitHubHookConfiguration `json:",inline"`
}

type GitHubHookConfiguration struct {
	Repositories              []string `json:"repositories"` // Target repositories (e.g. f110/heimdallr)
	Path                      string   `json:"path,omitempty"`
	Events                    []string `json:"events,omitempty"`
	ContentType               string   `json:"contentType,omitempty"`
	CredentialSecretName      string   `json:"credentialSecretName,omitempty"`
	CredentialSecretNamespace string   `json:"credentialSecretNamespace,omitempty"`
	AppIdKey                  string   `json:"appIdKey,omitempty,omitempty"`
	InstallationIdKey         string   `json:"installationIdKey,omitempty"`
	PrivateKeyKey             string   `json:"privateKeyKey,omitempty"`
}

type Permission struct {
	Name      string     `json:"name,omitempty"`
	Locations []Location `json:"locations,omitempty"`
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

// BackendStatus defines the observed state of Backend
type BackendStatus struct {
	DeployedBy            []*ProxyReference             `json:"deployedBy,omitempty"`
	WebhookConfigurations []*WebhookConfigurationStatus `json:"webhookConfiguration,omitempty"`
}

type ProxyReference struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Url       string `json:"url,omitempty"`
}

type WebhookConfigurationStatus struct {
	Id         int64       `json:"id"`
	Repository string      `json:"repository,omitempty"`
	UpdateTime metav1.Time `json:"updateTime,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// Backend is the Schema for the backends API
type Backend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendSpec   `json:"spec,omitempty"`
	Status BackendStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BackendList contains a list of Backend
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}

// RoleSpec defines the desired state of Role
type RoleSpec struct {
	Title          string `json:"title,omitempty"`
	Description    string `json:"description,omitempty"`
	AllowDashboard bool   `json:"allowDashboard,omitempty"`
}

type Binding struct {
	BackendName       string `json:"backendName,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Permission        string `json:"permission,omitempty"`
	RpcPermissionName string `json:"rpcPermissionName,omitempty"`
}

// RoleStatus defines the observed state of Role
type RoleStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// Role is the Schema for the roles API
type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RoleSpec   `json:"spec,omitempty"`
	Status RoleStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RoleList contains a list of Role
type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Role `json:"items"`
}

// RpcPermissionSpec defines the desired state of RpcPermission
type RpcPermissionSpec struct {
	Allow []string `json:"allow"`
}

// RpcPermissionStatus defines the observed state of RpcPermission
type RpcPermissionStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// RpcPermission is the Schema for the rpcpermissions API
type RpcPermission struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RpcPermissionSpec   `json:"spec,omitempty"`
	Status RpcPermissionStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RpcPermissionList contains a list of RpcPermission
type RpcPermissionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RpcPermission `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:storageversion
// +genclient:noStatus

type RoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Subjects []Subject `json:"subjects"`
	RoleRef  RoleRef   `json:"roleRef"`
}

type RoleRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type Subject struct {
	// Kind of object.
	// Value is "Backend" or "RpcPermission"
	Kind string `json:"kind"`
	// Name of object.
	Name string `json:"name"`
	// Namespace of object. If not set, will be use same namespace.
	Namespace string `json:"namespace,omitempty"`
	// Permission is the name of permission of backend.
	Permission string `json:"permission,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type RoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RoleBinding `json:"items"`
}
