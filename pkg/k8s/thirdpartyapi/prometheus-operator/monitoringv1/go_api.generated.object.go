package monitoringv1

import (
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilintstr "k8s.io/apimachinery/pkg/util/intstr"
)

const GroupName = "coreos.com.monitoring"

var (
	GroupVersion       = metav1.GroupVersion{Group: GroupName, Version: "v1"}
	SchemeBuilder      = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme        = SchemeBuilder.AddToScheme
	SchemaGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1"}
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemaGroupVersion,
		&Alertmanager{},
		&AlertmanagerList{},
		&PodMonitor{},
		&PodMonitorList{},
		&Probe{},
		&ProbeList{},
		&Prometheus{},
		&PrometheusList{},
		&PrometheusRule{},
		&PrometheusRuleList{},
		&ServiceMonitor{},
		&ServiceMonitorList{},
		&ThanosRuler{},
		&ThanosRulerList{},
	)
	metav1.AddToGroupVersion(scheme, SchemaGroupVersion)
	return nil
}

type PrometheusConditionStatus string

const (
	PrometheusConditionStatusTrue     PrometheusConditionStatus = "True"
	PrometheusConditionStatusDegraded PrometheusConditionStatus = "Degraded"
	PrometheusConditionStatusFalse    PrometheusConditionStatus = "False"
	PrometheusConditionStatusUnknown  PrometheusConditionStatus = "Unknown"
)

type PrometheusConditionType string

const (
	PrometheusConditionTypeAvailable  PrometheusConditionType = "Available"
	PrometheusConditionTypeReconciled PrometheusConditionType = "Reconciled"
)

type Alertmanager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Specification of the desired behavior of the Alertmanager cluster. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec AlertmanagerSpec `json:"spec"`
	// Most recent observed status of the Alertmanager cluster. Read-only. Not
	// included when requesting from the apiserver, only from the Prometheus
	// Operator API itself. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status *AlertmanagerStatus `json:"status,omitempty"`
}

func (in *Alertmanager) DeepCopyInto(out *Alertmanager) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(AlertmanagerStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *Alertmanager) DeepCopy() *Alertmanager {
	if in == nil {
		return nil
	}
	out := new(Alertmanager)
	in.DeepCopyInto(out)
	return out
}

func (in *Alertmanager) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type AlertmanagerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Alertmanager `json:"items"`
}

func (in *AlertmanagerList) DeepCopyInto(out *AlertmanagerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Alertmanager, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *AlertmanagerList) DeepCopy() *AlertmanagerList {
	if in == nil {
		return nil
	}
	out := new(AlertmanagerList)
	in.DeepCopyInto(out)
	return out
}

func (in *AlertmanagerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type PodMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Specification of desired Pod selection for target discovery by Prometheus.
	Spec PodMonitorSpec `json:"spec"`
}

func (in *PodMonitor) DeepCopyInto(out *PodMonitor) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *PodMonitor) DeepCopy() *PodMonitor {
	if in == nil {
		return nil
	}
	out := new(PodMonitor)
	in.DeepCopyInto(out)
	return out
}

func (in *PodMonitor) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type PodMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []PodMonitor `json:"items"`
}

func (in *PodMonitorList) DeepCopyInto(out *PodMonitorList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]PodMonitor, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *PodMonitorList) DeepCopy() *PodMonitorList {
	if in == nil {
		return nil
	}
	out := new(PodMonitorList)
	in.DeepCopyInto(out)
	return out
}

func (in *PodMonitorList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type Probe struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Specification of desired Ingress selection for target discovery by Prometheus.
	Spec ProbeSpec `json:"spec"`
}

func (in *Probe) DeepCopyInto(out *Probe) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *Probe) DeepCopy() *Probe {
	if in == nil {
		return nil
	}
	out := new(Probe)
	in.DeepCopyInto(out)
	return out
}

func (in *Probe) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ProbeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Probe `json:"items"`
}

func (in *ProbeList) DeepCopyInto(out *ProbeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Probe, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *ProbeList) DeepCopy() *ProbeList {
	if in == nil {
		return nil
	}
	out := new(ProbeList)
	in.DeepCopyInto(out)
	return out
}

func (in *ProbeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type Prometheus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Specification of the desired behavior of the Prometheus cluster. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec PrometheusSpec `json:"spec"`
	// Most recent observed status of the Prometheus cluster. Read-only.
	// More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status *PrometheusStatus `json:"status,omitempty"`
}

func (in *Prometheus) DeepCopyInto(out *Prometheus) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(PrometheusStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *Prometheus) DeepCopy() *Prometheus {
	if in == nil {
		return nil
	}
	out := new(Prometheus)
	in.DeepCopyInto(out)
	return out
}

func (in *Prometheus) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type PrometheusList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Prometheus `json:"items"`
}

func (in *PrometheusList) DeepCopyInto(out *PrometheusList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Prometheus, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *PrometheusList) DeepCopy() *PrometheusList {
	if in == nil {
		return nil
	}
	out := new(PrometheusList)
	in.DeepCopyInto(out)
	return out
}

func (in *PrometheusList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type PrometheusRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Specification of desired alerting rule definitions for Prometheus.
	Spec PrometheusRuleSpec `json:"spec"`
}

func (in *PrometheusRule) DeepCopyInto(out *PrometheusRule) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *PrometheusRule) DeepCopy() *PrometheusRule {
	if in == nil {
		return nil
	}
	out := new(PrometheusRule)
	in.DeepCopyInto(out)
	return out
}

func (in *PrometheusRule) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type PrometheusRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []PrometheusRule `json:"items"`
}

func (in *PrometheusRuleList) DeepCopyInto(out *PrometheusRuleList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]PrometheusRule, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *PrometheusRuleList) DeepCopy() *PrometheusRuleList {
	if in == nil {
		return nil
	}
	out := new(PrometheusRuleList)
	in.DeepCopyInto(out)
	return out
}

func (in *PrometheusRuleList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ServiceMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Specification of desired Service selection for target discovery by
	// Prometheus.
	Spec ServiceMonitorSpec `json:"spec"`
}

func (in *ServiceMonitor) DeepCopyInto(out *ServiceMonitor) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *ServiceMonitor) DeepCopy() *ServiceMonitor {
	if in == nil {
		return nil
	}
	out := new(ServiceMonitor)
	in.DeepCopyInto(out)
	return out
}

func (in *ServiceMonitor) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ServiceMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ServiceMonitor `json:"items"`
}

func (in *ServiceMonitorList) DeepCopyInto(out *ServiceMonitorList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]ServiceMonitor, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *ServiceMonitorList) DeepCopy() *ServiceMonitorList {
	if in == nil {
		return nil
	}
	out := new(ServiceMonitorList)
	in.DeepCopyInto(out)
	return out
}

func (in *ServiceMonitorList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ThanosRuler struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Specification of the desired behavior of the ThanosRuler cluster. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec ThanosRulerSpec `json:"spec"`
	// Most recent observed status of the ThanosRuler cluster. Read-only. Not
	// included when requesting from the apiserver, only from the ThanosRuler
	// Operator API itself. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status *ThanosRulerStatus `json:"status,omitempty"`
}

func (in *ThanosRuler) DeepCopyInto(out *ThanosRuler) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(ThanosRulerStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ThanosRuler) DeepCopy() *ThanosRuler {
	if in == nil {
		return nil
	}
	out := new(ThanosRuler)
	in.DeepCopyInto(out)
	return out
}

func (in *ThanosRuler) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ThanosRulerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ThanosRuler `json:"items"`
}

func (in *ThanosRulerList) DeepCopyInto(out *ThanosRulerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]ThanosRuler, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *ThanosRulerList) DeepCopy() *ThanosRulerList {
	if in == nil {
		return nil
	}
	out := new(ThanosRulerList)
	in.DeepCopyInto(out)
	return out
}

func (in *ThanosRulerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type AlertmanagerSpec struct {
	// PodMetadata configures Labels and Annotations which are propagated to the alertmanager pods.
	PodMetadata *EmbeddedObjectMetadata `json:"podMetadata,omitempty"`
	// Image if specified has precedence over baseImage, tag and sha
	// combinations. Specifying the version is still necessary to ensure the
	// Prometheus Operator knows what version of Alertmanager is being
	// configured.
	Image string `json:"image,omitempty"`
	// Version the cluster should be on.
	Version string `json:"version,omitempty"`
	// Tag of Alertmanager container image to be deployed. Defaults to the value of `version`.
	// Version is ignored if Tag is set.
	// Deprecated: use 'image' instead.  The image tag can be specified
	// as part of the image URL.
	Tag string `json:"tag,omitempty"`
	// SHA of Alertmanager container image to be deployed. Defaults to the value of `version`.
	// Similar to a tag, but the SHA explicitly deploys an immutable container image.
	// Version and Tag are ignored if SHA is set.
	// Deprecated: use 'image' instead.  The image digest can be specified
	// as part of the image URL.
	SHA string `json:"sha,omitempty"`
	// Base image that is used to deploy pods, without tag.
	// Deprecated: use 'image' instead
	BaseImage string `json:"baseImage,omitempty"`
	// An optional list of references to secrets in the same namespace
	// to use for pulling prometheus and alertmanager images from registries
	// see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// Secrets is a list of Secrets in the same namespace as the Alertmanager
	// object, which shall be mounted into the Alertmanager Pods.
	// The Secrets are mounted into /etc/alertmanager/secrets/<secret-name>.
	Secrets []string `json:"secrets"`
	// ConfigMaps is a list of ConfigMaps in the same namespace as the Alertmanager
	// object, which shall be mounted into the Alertmanager Pods.
	// The ConfigMaps are mounted into /etc/alertmanager/configmaps/<configmap-name>.
	ConfigMaps []string `json:"configMaps"`
	// ConfigSecret is the name of a Kubernetes Secret in the same namespace as the
	// Alertmanager object, which contains the configuration for this Alertmanager
	// instance. If empty, it defaults to 'alertmanager-<alertmanager-name>'.
	// The Alertmanager configuration should be available under the
	// `alertmanager.yaml` key. Additional keys from the original secret are
	// copied to the generated secret.
	// If either the secret or the `alertmanager.yaml` key is missing, the
	// operator provisions an Alertmanager configuration with one empty
	// receiver (effectively dropping alert notifications).
	ConfigSecret string `json:"configSecret,omitempty"`
	// Log level for Alertmanager to be configured with.
	LogLevel string `json:"logLevel,omitempty"`
	// Log format for Alertmanager to be configured with.
	LogFormat string `json:"logFormat,omitempty"`
	// Size is the expected size of the alertmanager cluster. The controller will
	// eventually make the size of the running cluster equal to the expected
	// size.
	Replicas int `json:"replicas,omitempty"`
	// Time duration Alertmanager shall retain data for. Default is '120h',
	// and must match the regular expression `[0-9]+(ms|s|m|h)` (milliseconds seconds minutes hours).
	Retention string `json:"retention"`
	// Storage is the definition of how storage will be used by the Alertmanager
	// instances.
	Storage *StorageSpec `json:"storage,omitempty"`
	// Volumes allows configuration of additional volumes on the output StatefulSet definition.
	// Volumes specified will be appended to other volumes that are generated as a result of
	// StorageSpec objects.
	Volumes []corev1.Volume `json:"volumes"`
	// VolumeMounts allows configuration of additional VolumeMounts on the output StatefulSet definition.
	// VolumeMounts specified will be appended to other VolumeMounts in the alertmanager container,
	// that are generated as a result of StorageSpec objects.
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts"`
	// The external URL the Alertmanager instances will be available under. This is
	// necessary to generate correct URLs. This is necessary if Alertmanager is not
	// served from root of a DNS name.
	ExternalURL string `json:"externalUrl,omitempty"`
	// The route prefix Alertmanager registers HTTP handlers for. This is useful,
	// if using ExternalURL and a proxy is rewriting HTTP routes of a request,
	// and the actual ExternalURL is still true, but the server serves requests
	// under a different route prefix. For example for use with `kubectl proxy`.
	RoutePrefix string `json:"routePrefix,omitempty"`
	// If set to true all actions on the underlying managed objects are not
	// goint to be performed, except for delete actions.
	Paused bool `json:"paused,omitempty"`
	// Define which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Define resources requests and limits for single Pods.
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// If specified, the pod's scheduling constraints.
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// If specified, the pod's tolerations.
	Tolerations []corev1.Toleration `json:"tolerations"`
	// If specified, the pod's topology spread constraints.
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints"`
	// SecurityContext holds pod-level security attributes and common container settings.
	// This defaults to the default PodSecurityContext.
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	// ServiceAccountName is the name of the ServiceAccount to use to run the
	// Prometheus Pods.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// ListenLocal makes the Alertmanager server listen on loopback, so that it
	// does not bind against the Pod IP. Note this is only for the Alertmanager
	// UI, not the gossip communication.
	ListenLocal bool `json:"listenLocal,omitempty"`
	// Containers allows injecting additional containers. This is meant to
	// allow adding an authentication proxy to an Alertmanager pod.
	// Containers described here modify an operator generated container if they
	// share the same name and modifications are done via a strategic merge
	// patch. The current container names are: `alertmanager` and
	// `config-reloader`. Overriding containers is entirely outside the scope
	// of what the maintainers will support and by doing so, you accept that
	// this behaviour may break at any time without notice.
	Containers []corev1.Container `json:"containers"`
	// InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
	// fetch secrets for injection into the Alertmanager configuration from external sources. Any
	// errors during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
	// Using initContainers for any use case other then secret fetching is entirely outside the scope
	// of what the maintainers will support and by doing so, you accept that this behaviour may break
	// at any time without notice.
	InitContainers []corev1.Container `json:"initContainers"`
	// Priority class assigned to the Pods
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// AdditionalPeers allows injecting a set of additional Alertmanagers to peer with to form a highly available cluster.
	AdditionalPeers []string `json:"additionalPeers"`
	// ClusterAdvertiseAddress is the explicit address to advertise in cluster.
	// Needs to be provided for non RFC1918 [1] (public) addresses.
	// [1] RFC1918: https://tools.ietf.org/html/rfc1918
	ClusterAdvertiseAddress string `json:"clusterAdvertiseAddress,omitempty"`
	// Interval between gossip attempts.
	ClusterGossipInterval string `json:"clusterGossipInterval"`
	// Interval between pushpull attempts.
	ClusterPushpullInterval string `json:"clusterPushpullInterval"`
	// Timeout for cluster peering.
	ClusterPeerTimeout string `json:"clusterPeerTimeout"`
	// Port name used for the pods and governing service.
	// This defaults to web
	PortName string `json:"portName,omitempty"`
	// ForceEnableClusterMode ensures Alertmanager does not deactivate the cluster mode when running with a single replica.
	// Use case is e.g. spanning an Alertmanager cluster across Kubernetes clusters with a single replica in each.
	ForceEnableClusterMode bool `json:"forceEnableClusterMode,omitempty"`
	// AlertmanagerConfigs to be selected for to merge and configure Alertmanager with.
	AlertmanagerConfigSelector *metav1.LabelSelector `json:"alertmanagerConfigSelector,omitempty"`
	// Namespaces to be selected for AlertmanagerConfig discovery. If nil, only
	// check own namespace.
	AlertmanagerConfigNamespaceSelector *metav1.LabelSelector `json:"alertmanagerConfigNamespaceSelector,omitempty"`
	// Minimum number of seconds for which a newly created pod should be ready
	// without any of its container crashing for it to be considered available.
	// Defaults to 0 (pod will be considered available as soon as it is ready)
	// This is an alpha field and requires enabling StatefulSetMinReadySeconds feature gate.
	MinReadySeconds uint32 `json:"minReadySeconds,omitempty"`
	// Pods' hostAliases configuration
	HostAliases []HostAlias `json:"hostAliases"`
	// Defines the web command line flags when starting Alertmanager.
	Web *AlertmanagerWebSpec `json:"web,omitempty"`
	// EXPERIMENTAL: alertmanagerConfiguration specifies the configuration of Alertmanager.
	// If defined, it takes precedence over the `configSecret` field.
	// This field may change in future releases.
	AlertmanagerConfiguration *AlertmanagerConfiguration `json:"alertmanagerConfiguration,omitempty"`
}

func (in *AlertmanagerSpec) DeepCopyInto(out *AlertmanagerSpec) {
	*out = *in
	if in.PodMetadata != nil {
		in, out := &in.PodMetadata, &out.PodMetadata
		*out = new(EmbeddedObjectMetadata)
		(*in).DeepCopyInto(*out)
	}
	if in.ImagePullSecrets != nil {
		l := make([]corev1.LocalObjectReference, len(in.ImagePullSecrets))
		for i := range in.ImagePullSecrets {
			in.ImagePullSecrets[i].DeepCopyInto(&l[i])
		}
		out.ImagePullSecrets = l
	}
	if in.Secrets != nil {
		t := make([]string, len(in.Secrets))
		copy(t, in.Secrets)
		out.Secrets = t
	}
	if in.ConfigMaps != nil {
		t := make([]string, len(in.ConfigMaps))
		copy(t, in.ConfigMaps)
		out.ConfigMaps = t
	}
	if in.Storage != nil {
		in, out := &in.Storage, &out.Storage
		*out = new(StorageSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Volumes != nil {
		l := make([]corev1.Volume, len(in.Volumes))
		for i := range in.Volumes {
			in.Volumes[i].DeepCopyInto(&l[i])
		}
		out.Volumes = l
	}
	if in.VolumeMounts != nil {
		l := make([]corev1.VolumeMount, len(in.VolumeMounts))
		for i := range in.VolumeMounts {
			in.VolumeMounts[i].DeepCopyInto(&l[i])
		}
		out.VolumeMounts = l
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(corev1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	if in.Affinity != nil {
		in, out := &in.Affinity, &out.Affinity
		*out = new(corev1.Affinity)
		(*in).DeepCopyInto(*out)
	}
	if in.Tolerations != nil {
		l := make([]corev1.Toleration, len(in.Tolerations))
		for i := range in.Tolerations {
			in.Tolerations[i].DeepCopyInto(&l[i])
		}
		out.Tolerations = l
	}
	if in.TopologySpreadConstraints != nil {
		l := make([]corev1.TopologySpreadConstraint, len(in.TopologySpreadConstraints))
		for i := range in.TopologySpreadConstraints {
			in.TopologySpreadConstraints[i].DeepCopyInto(&l[i])
		}
		out.TopologySpreadConstraints = l
	}
	if in.SecurityContext != nil {
		in, out := &in.SecurityContext, &out.SecurityContext
		*out = new(corev1.PodSecurityContext)
		(*in).DeepCopyInto(*out)
	}
	if in.Containers != nil {
		l := make([]corev1.Container, len(in.Containers))
		for i := range in.Containers {
			in.Containers[i].DeepCopyInto(&l[i])
		}
		out.Containers = l
	}
	if in.InitContainers != nil {
		l := make([]corev1.Container, len(in.InitContainers))
		for i := range in.InitContainers {
			in.InitContainers[i].DeepCopyInto(&l[i])
		}
		out.InitContainers = l
	}
	if in.AdditionalPeers != nil {
		t := make([]string, len(in.AdditionalPeers))
		copy(t, in.AdditionalPeers)
		out.AdditionalPeers = t
	}
	if in.AlertmanagerConfigSelector != nil {
		in, out := &in.AlertmanagerConfigSelector, &out.AlertmanagerConfigSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.AlertmanagerConfigNamespaceSelector != nil {
		in, out := &in.AlertmanagerConfigNamespaceSelector, &out.AlertmanagerConfigNamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.HostAliases != nil {
		l := make([]HostAlias, len(in.HostAliases))
		for i := range in.HostAliases {
			in.HostAliases[i].DeepCopyInto(&l[i])
		}
		out.HostAliases = l
	}
	if in.Web != nil {
		in, out := &in.Web, &out.Web
		*out = new(AlertmanagerWebSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.AlertmanagerConfiguration != nil {
		in, out := &in.AlertmanagerConfiguration, &out.AlertmanagerConfiguration
		*out = new(AlertmanagerConfiguration)
		(*in).DeepCopyInto(*out)
	}
}

func (in *AlertmanagerSpec) DeepCopy() *AlertmanagerSpec {
	if in == nil {
		return nil
	}
	out := new(AlertmanagerSpec)
	in.DeepCopyInto(out)
	return out
}

type AlertmanagerStatus struct {
	// Represents whether any actions on the underlying managed objects are
	// being performed. Only delete actions will be performed.
	Paused bool `json:"paused"`
	// Total number of non-terminated pods targeted by this Alertmanager
	// cluster (their labels match the selector).
	Replicas int `json:"replicas"`
	// Total number of non-terminated pods targeted by this Alertmanager
	// cluster that have the desired version spec.
	UpdatedReplicas int `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this Alertmanager cluster.
	AvailableReplicas int `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this Alertmanager cluster.
	UnavailableReplicas int `json:"unavailableReplicas"`
}

func (in *AlertmanagerStatus) DeepCopyInto(out *AlertmanagerStatus) {
	*out = *in
}

func (in *AlertmanagerStatus) DeepCopy() *AlertmanagerStatus {
	if in == nil {
		return nil
	}
	out := new(AlertmanagerStatus)
	in.DeepCopyInto(out)
	return out
}

type PodMonitorSpec struct {
	// The label to use to retrieve the job name from.
	JobLabel string `json:"jobLabel,omitempty"`
	// PodTargetLabels transfers labels on the Kubernetes Pod onto the target.
	PodTargetLabels []string `json:"podTargetLabels"`
	// A list of endpoints allowed as part of this PodMonitor.
	PodMetricsEndpoints []PodMetricsEndpoint `json:"podMetricsEndpoints"`
	// Selector to select Pod objects.
	Selector metav1.LabelSelector `json:"selector"`
	// Selector to select which namespaces the Endpoints objects are discovered from.
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`
	// SampleLimit defines per-scrape limit on number of scraped samples that will be accepted.
	SampleLimit uint64 `json:"sampleLimit,omitempty"`
	// TargetLimit defines a limit on the number of scraped targets that will be accepted.
	TargetLimit uint64 `json:"targetLimit,omitempty"`
	// Per-scrape limit on number of labels that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelLimit uint64 `json:"labelLimit,omitempty"`
	// Per-scrape limit on length of labels name that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelNameLengthLimit uint64 `json:"labelNameLengthLimit,omitempty"`
	// Per-scrape limit on length of labels value that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelValueLengthLimit uint64 `json:"labelValueLengthLimit,omitempty"`
	// Attaches node metadata to discovered targets. Only valid for role: pod.
	// Only valid in Prometheus versions 2.35.0 and newer.
	AttachMetadata *AttachMetadata `json:"attachMetadata,omitempty"`
}

func (in *PodMonitorSpec) DeepCopyInto(out *PodMonitorSpec) {
	*out = *in
	if in.PodTargetLabels != nil {
		t := make([]string, len(in.PodTargetLabels))
		copy(t, in.PodTargetLabels)
		out.PodTargetLabels = t
	}
	if in.PodMetricsEndpoints != nil {
		l := make([]PodMetricsEndpoint, len(in.PodMetricsEndpoints))
		for i := range in.PodMetricsEndpoints {
			in.PodMetricsEndpoints[i].DeepCopyInto(&l[i])
		}
		out.PodMetricsEndpoints = l
	}
	in.Selector.DeepCopyInto(&out.Selector)
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(NamespaceSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.AttachMetadata != nil {
		in, out := &in.AttachMetadata, &out.AttachMetadata
		*out = new(AttachMetadata)
		(*in).DeepCopyInto(*out)
	}
}

func (in *PodMonitorSpec) DeepCopy() *PodMonitorSpec {
	if in == nil {
		return nil
	}
	out := new(PodMonitorSpec)
	in.DeepCopyInto(out)
	return out
}

type ProbeSpec struct {
	// The job name assigned to scraped metrics by default.
	JobName string `json:"jobName,omitempty"`
	// Specification for the prober to use for probing targets.
	// The prober.URL parameter is required. Targets cannot be probed if left empty.
	ProberSpec *ProberSpec `json:"prober,omitempty"`
	// The module to use for probing specifying how to probe the target.
	// Example module configuring in the blackbox exporter:
	// https://github.com/prometheus/blackbox_exporter/blob/master/example.yml
	Module string `json:"module,omitempty"`
	// Targets defines a set of static or dynamically discovered targets to probe.
	Targets *ProbeTargets `json:"targets,omitempty"`
	// Interval at which targets are probed using the configured prober.
	// If not specified Prometheus' global scrape interval is used.
	Interval string `json:"interval"`
	// Timeout for scraping metrics from the Prometheus exporter.
	// If not specified, the Prometheus global scrape interval is used.
	ScrapeTimeout string `json:"scrapeTimeout"`
	// TLS configuration to use when scraping the endpoint.
	TLSConfig *ProbeTLSConfig `json:"tlsConfig,omitempty"`
	// Secret to mount to read bearer token for scraping targets. The secret
	// needs to be in the same namespace as the probe and accessible by
	// the Prometheus Operator.
	BearerTokenSecret *corev1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// BasicAuth allow an endpoint to authenticate over basic authentication.
	// More info: https://prometheus.io/docs/operating/configuration/#endpoint
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Oauth2 for the URL. Only valid in Prometheus versions 2.27.0 and newer.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// MetricRelabelConfigs to apply to samples before ingestion.
	MetricRelabelConfigs []RelabelConfig `json:"metricRelabelings"`
	// Authorization section for this endpoint
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// SampleLimit defines per-scrape limit on number of scraped samples that will be accepted.
	SampleLimit uint64 `json:"sampleLimit,omitempty"`
	// TargetLimit defines a limit on the number of scraped targets that will be accepted.
	TargetLimit uint64 `json:"targetLimit,omitempty"`
	// Per-scrape limit on number of labels that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelLimit uint64 `json:"labelLimit,omitempty"`
	// Per-scrape limit on length of labels name that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelNameLengthLimit uint64 `json:"labelNameLengthLimit,omitempty"`
	// Per-scrape limit on length of labels value that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelValueLengthLimit uint64 `json:"labelValueLengthLimit,omitempty"`
}

func (in *ProbeSpec) DeepCopyInto(out *ProbeSpec) {
	*out = *in
	if in.ProberSpec != nil {
		in, out := &in.ProberSpec, &out.ProberSpec
		*out = new(ProberSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Targets != nil {
		in, out := &in.Targets, &out.Targets
		*out = new(ProbeTargets)
		(*in).DeepCopyInto(*out)
	}
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(ProbeTLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.BearerTokenSecret != nil {
		in, out := &in.BearerTokenSecret, &out.BearerTokenSecret
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.OAuth2 != nil {
		in, out := &in.OAuth2, &out.OAuth2
		*out = new(OAuth2)
		(*in).DeepCopyInto(*out)
	}
	if in.MetricRelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.MetricRelabelConfigs))
		for i := range in.MetricRelabelConfigs {
			in.MetricRelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.MetricRelabelConfigs = l
	}
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(SafeAuthorization)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ProbeSpec) DeepCopy() *ProbeSpec {
	if in == nil {
		return nil
	}
	out := new(ProbeSpec)
	in.DeepCopyInto(out)
	return out
}

type PrometheusSpec struct {
	CommonPrometheusFields `json:",inline"`
	// Base image to use for a Prometheus deployment.
	// Deprecated: use 'image' instead
	BaseImage string `json:"baseImage,omitempty"`
	// Tag of Prometheus container image to be deployed. Defaults to the value of `version`.
	// Version is ignored if Tag is set.
	// Deprecated: use 'image' instead.  The image tag can be specified
	// as part of the image URL.
	Tag string `json:"tag,omitempty"`
	// SHA of Prometheus container image to be deployed. Defaults to the value of `version`.
	// Similar to a tag, but the SHA explicitly deploys an immutable container image.
	// Version and Tag are ignored if SHA is set.
	// Deprecated: use 'image' instead.  The image digest can be specified
	// as part of the image URL.
	SHA string `json:"sha,omitempty"`
	// Time duration Prometheus shall retain data for. Default is '24h' if
	// retentionSize is not set, and must match the regular expression `[0-9]+(ms|s|m|h|d|w|y)`
	// (milliseconds seconds minutes hours days weeks years).
	Retention string `json:"retention"`
	// Maximum amount of disk space used by blocks.
	RetentionSize string `json:"retentionSize"`
	// Disable prometheus compaction.
	DisableCompaction bool `json:"disableCompaction,omitempty"`
	// /--rules.*/ command-line arguments.
	Rules *Rules `json:"rules,omitempty"`
	// PrometheusRulesExcludedFromEnforce - list of prometheus rules to be excluded from enforcing
	// of adding namespace labels. Works only if enforcedNamespaceLabel set to true.
	// Make sure both ruleNamespace and ruleName are set for each pair.
	// Deprecated: use excludedFromEnforcement instead.
	PrometheusRulesExcludedFromEnforce []PrometheusRuleExcludeConfig `json:"prometheusRulesExcludedFromEnforce"`
	// QuerySpec defines the query command line flags when starting Prometheus.
	Query *QuerySpec `json:"query,omitempty"`
	// A selector to select which PrometheusRules to mount for loading alerting/recording
	// rules from. Until (excluding) Prometheus Operator v0.24.0 Prometheus
	// Operator will migrate any legacy rule ConfigMaps to PrometheusRule custom
	// resources selected by RuleSelector. Make sure it does not match any config
	// maps that you do not want to be migrated.
	RuleSelector *metav1.LabelSelector `json:"ruleSelector,omitempty"`
	// Namespaces to be selected for PrometheusRules discovery. If unspecified, only
	// the same namespace as the Prometheus object is in is used.
	RuleNamespaceSelector *metav1.LabelSelector `json:"ruleNamespaceSelector,omitempty"`
	// Define details regarding alerting.
	Alerting *AlertingSpec `json:"alerting,omitempty"`
	// remoteRead is the list of remote read configurations.
	RemoteRead []RemoteReadSpec `json:"remoteRead"`
	// AdditionalAlertRelabelConfigs allows specifying a key of a Secret containing
	// additional Prometheus alert relabel configurations. Alert relabel configurations
	// specified are appended to the configurations generated by the Prometheus
	// Operator. Alert relabel configurations specified must have the form as specified
	// in the official Prometheus documentation:
	// https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alert_relabel_configs.
	// As alert relabel configs are appended, the user is responsible to make sure it
	// is valid. Note that using this feature may expose the possibility to
	// break upgrades of Prometheus. It is advised to review Prometheus release
	// notes to ensure that no incompatible alert relabel configs are going to break
	// Prometheus after the upgrade.
	AdditionalAlertRelabelConfigs *corev1.SecretKeySelector `json:"additionalAlertRelabelConfigs,omitempty"`
	// AdditionalAlertManagerConfigs allows specifying a key of a Secret containing
	// additional Prometheus AlertManager configurations. AlertManager configurations
	// specified are appended to the configurations generated by the Prometheus
	// Operator. Job configurations specified must have the form as specified
	// in the official Prometheus documentation:
	// https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alertmanager_config.
	// As AlertManager configs are appended, the user is responsible to make sure it
	// is valid. Note that using this feature may expose the possibility to
	// break upgrades of Prometheus. It is advised to review Prometheus release
	// notes to ensure that no incompatible AlertManager configs are going to break
	// Prometheus after the upgrade.
	AdditionalAlertManagerConfigs *corev1.SecretKeySelector `json:"additionalAlertManagerConfigs,omitempty"`
	// Thanos configuration allows configuring various aspects of a Prometheus
	// server in a Thanos environment.
	// This section is experimental, it may change significantly without
	// deprecation notice in any release.
	// This is experimental and may change significantly without backward
	// compatibility in any release.
	Thanos *ThanosSpec `json:"thanos,omitempty"`
	// QueryLogFile specifies the file to which PromQL queries are logged.
	// If the filename has an empty path, e.g. 'query.log', prometheus-operator will mount the file into an
	// emptyDir volume at `/var/log/prometheus`. If a full path is provided, e.g. /var/log/prometheus/query.log, you must mount a volume
	// in the specified directory and it must be writable. This is because the prometheus container runs with a read-only root filesystem for security reasons.
	// Alternatively, the location can be set to a stdout location such as `/dev/stdout` to log
	// query information to the default Prometheus log stream.
	// This is only available in versions of Prometheus >= 2.16.0.
	// For more details, see the Prometheus docs (https://prometheus.io/docs/guides/query-log/)
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// AllowOverlappingBlocks enables vertical compaction and vertical query merge in Prometheus.
	// This is still experimental in Prometheus so it may change in any upcoming release.
	AllowOverlappingBlocks bool `json:"allowOverlappingBlocks,omitempty"`
	// Exemplars related settings that are runtime reloadable.
	// It requires to enable the exemplar storage feature to be effective.
	Exemplars *Exemplars `json:"exemplars,omitempty"`
	// Interval between consecutive evaluations. Default: `30s`
	EvaluationInterval string `json:"evaluationInterval"`
	// Enable access to prometheus web admin API. Defaults to the value of `false`.
	// WARNING: Enabling the admin APIs enables mutating endpoints, to delete data,
	// shutdown Prometheus, and more. Enabling this should be done with care and the
	// user is advised to add additional authentication authorization via a proxy to
	// ensure only clients authorized to perform these actions can do so.
	// For more information see https://prometheus.io/docs/prometheus/latest/querying/api/#tsdb-admin-apis
	EnableAdminAPI bool `json:"enableAdminAPI,omitempty"`
}

func (in *PrometheusSpec) DeepCopyInto(out *PrometheusSpec) {
	*out = *in
	out.CommonPrometheusFields = in.CommonPrometheusFields
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = new(Rules)
		(*in).DeepCopyInto(*out)
	}
	if in.PrometheusRulesExcludedFromEnforce != nil {
		l := make([]PrometheusRuleExcludeConfig, len(in.PrometheusRulesExcludedFromEnforce))
		for i := range in.PrometheusRulesExcludedFromEnforce {
			in.PrometheusRulesExcludedFromEnforce[i].DeepCopyInto(&l[i])
		}
		out.PrometheusRulesExcludedFromEnforce = l
	}
	if in.Query != nil {
		in, out := &in.Query, &out.Query
		*out = new(QuerySpec)
		(*in).DeepCopyInto(*out)
	}
	if in.RuleSelector != nil {
		in, out := &in.RuleSelector, &out.RuleSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.RuleNamespaceSelector != nil {
		in, out := &in.RuleNamespaceSelector, &out.RuleNamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Alerting != nil {
		in, out := &in.Alerting, &out.Alerting
		*out = new(AlertingSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.RemoteRead != nil {
		l := make([]RemoteReadSpec, len(in.RemoteRead))
		for i := range in.RemoteRead {
			in.RemoteRead[i].DeepCopyInto(&l[i])
		}
		out.RemoteRead = l
	}
	if in.AdditionalAlertRelabelConfigs != nil {
		in, out := &in.AdditionalAlertRelabelConfigs, &out.AdditionalAlertRelabelConfigs
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.AdditionalAlertManagerConfigs != nil {
		in, out := &in.AdditionalAlertManagerConfigs, &out.AdditionalAlertManagerConfigs
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Thanos != nil {
		in, out := &in.Thanos, &out.Thanos
		*out = new(ThanosSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Exemplars != nil {
		in, out := &in.Exemplars, &out.Exemplars
		*out = new(Exemplars)
		(*in).DeepCopyInto(*out)
	}
}

func (in *PrometheusSpec) DeepCopy() *PrometheusSpec {
	if in == nil {
		return nil
	}
	out := new(PrometheusSpec)
	in.DeepCopyInto(out)
	return out
}

type PrometheusStatus struct {
	// Represents whether any actions on the underlying managed objects are
	// being performed. Only delete actions will be performed.
	Paused bool `json:"paused"`
	// Total number of non-terminated pods targeted by this Prometheus deployment
	// (their labels match the selector).
	Replicas int `json:"replicas"`
	// Total number of non-terminated pods targeted by this Prometheus deployment
	// that have the desired version spec.
	UpdatedReplicas int `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this Prometheus deployment.
	AvailableReplicas int `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this Prometheus deployment.
	UnavailableReplicas int `json:"unavailableReplicas"`
	// The current state of the Prometheus deployment.
	Conditions []PrometheusCondition `json:"conditions"`
	// The list has one entry per shard. Each entry provides a summary of the shard status.
	ShardStatuses []ShardStatus `json:"shardStatuses"`
}

func (in *PrometheusStatus) DeepCopyInto(out *PrometheusStatus) {
	*out = *in
	if in.Conditions != nil {
		l := make([]PrometheusCondition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&l[i])
		}
		out.Conditions = l
	}
	if in.ShardStatuses != nil {
		l := make([]ShardStatus, len(in.ShardStatuses))
		for i := range in.ShardStatuses {
			in.ShardStatuses[i].DeepCopyInto(&l[i])
		}
		out.ShardStatuses = l
	}
}

func (in *PrometheusStatus) DeepCopy() *PrometheusStatus {
	if in == nil {
		return nil
	}
	out := new(PrometheusStatus)
	in.DeepCopyInto(out)
	return out
}

type PrometheusRuleSpec struct {
	// Content of Prometheus rule file
	Groups []RuleGroup `json:"groups"`
}

func (in *PrometheusRuleSpec) DeepCopyInto(out *PrometheusRuleSpec) {
	*out = *in
	if in.Groups != nil {
		l := make([]RuleGroup, len(in.Groups))
		for i := range in.Groups {
			in.Groups[i].DeepCopyInto(&l[i])
		}
		out.Groups = l
	}
}

func (in *PrometheusRuleSpec) DeepCopy() *PrometheusRuleSpec {
	if in == nil {
		return nil
	}
	out := new(PrometheusRuleSpec)
	in.DeepCopyInto(out)
	return out
}

type ServiceMonitorSpec struct {
	// JobLabel selects the label from the associated Kubernetes service which will be used as the `job` label for all metrics.
	// For example:
	// If in `ServiceMonitor.spec.jobLabel: foo` and in `Service.metadata.labels.foo: bar`,
	// then the `job="bar"` label is added to all metrics.
	// If the value of this field is empty or if the label doesn't exist for the given Service, the `job` label of the metrics defaults to the name of the Kubernetes Service.
	JobLabel string `json:"jobLabel,omitempty"`
	// TargetLabels transfers labels from the Kubernetes `Service` onto the created metrics.
	TargetLabels []string `json:"targetLabels"`
	// PodTargetLabels transfers labels on the Kubernetes `Pod` onto the created metrics.
	PodTargetLabels []string `json:"podTargetLabels"`
	// A list of endpoints allowed as part of this ServiceMonitor.
	Endpoints []Endpoint `json:"endpoints"`
	// Selector to select Endpoints objects.
	Selector metav1.LabelSelector `json:"selector"`
	// Selector to select which namespaces the Kubernetes Endpoints objects are discovered from.
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`
	// SampleLimit defines per-scrape limit on number of scraped samples that will be accepted.
	SampleLimit uint64 `json:"sampleLimit,omitempty"`
	// TargetLimit defines a limit on the number of scraped targets that will be accepted.
	TargetLimit uint64 `json:"targetLimit,omitempty"`
	// Per-scrape limit on number of labels that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelLimit uint64 `json:"labelLimit,omitempty"`
	// Per-scrape limit on length of labels name that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelNameLengthLimit uint64 `json:"labelNameLengthLimit,omitempty"`
	// Per-scrape limit on length of labels value that will be accepted for a sample.
	// Only valid in Prometheus versions 2.27.0 and newer.
	LabelValueLengthLimit uint64 `json:"labelValueLengthLimit,omitempty"`
}

func (in *ServiceMonitorSpec) DeepCopyInto(out *ServiceMonitorSpec) {
	*out = *in
	if in.TargetLabels != nil {
		t := make([]string, len(in.TargetLabels))
		copy(t, in.TargetLabels)
		out.TargetLabels = t
	}
	if in.PodTargetLabels != nil {
		t := make([]string, len(in.PodTargetLabels))
		copy(t, in.PodTargetLabels)
		out.PodTargetLabels = t
	}
	if in.Endpoints != nil {
		l := make([]Endpoint, len(in.Endpoints))
		for i := range in.Endpoints {
			in.Endpoints[i].DeepCopyInto(&l[i])
		}
		out.Endpoints = l
	}
	in.Selector.DeepCopyInto(&out.Selector)
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(NamespaceSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ServiceMonitorSpec) DeepCopy() *ServiceMonitorSpec {
	if in == nil {
		return nil
	}
	out := new(ServiceMonitorSpec)
	in.DeepCopyInto(out)
	return out
}

type ThanosRulerSpec struct {
	// PodMetadata contains Labels and Annotations gets propagated to the thanos ruler pods.
	PodMetadata *EmbeddedObjectMetadata `json:"podMetadata,omitempty"`
	// Thanos container image URL.
	Image string `json:"image,omitempty"`
	// An optional list of references to secrets in the same namespace
	// to use for pulling thanos images from registries
	// see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// When a ThanosRuler deployment is paused, no actions except for deletion
	// will be performed on the underlying objects.
	Paused bool `json:"paused,omitempty"`
	// Number of thanos ruler instances to deploy.
	Replicas int `json:"replicas,omitempty"`
	// Define which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources defines the resource requirements for single Pods.
	// If not provided, no requests/limits will be set
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// If specified, the pod's scheduling constraints.
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// If specified, the pod's tolerations.
	Tolerations []corev1.Toleration `json:"tolerations"`
	// If specified, the pod's topology spread constraints.
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints"`
	// SecurityContext holds pod-level security attributes and common container settings.
	// This defaults to the default PodSecurityContext.
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	// Priority class assigned to the Pods
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// ServiceAccountName is the name of the ServiceAccount to use to run the
	// Thanos Ruler Pods.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Storage spec to specify how storage shall be used.
	Storage *StorageSpec `json:"storage,omitempty"`
	// Volumes allows configuration of additional volumes on the output StatefulSet definition. Volumes specified will
	// be appended to other volumes that are generated as a result of StorageSpec objects.
	Volumes []corev1.Volume `json:"volumes"`
	// ObjectStorageConfig configures object storage in Thanos.
	// Alternative to ObjectStorageConfigFile, and lower order priority.
	ObjectStorageConfig *corev1.SecretKeySelector `json:"objectStorageConfig,omitempty"`
	// ObjectStorageConfigFile specifies the path of the object storage configuration file.
	// When used alongside with ObjectStorageConfig, ObjectStorageConfigFile takes precedence.
	ObjectStorageConfigFile string `json:"objectStorageConfigFile,omitempty"`
	// ListenLocal makes the Thanos ruler listen on loopback, so that it
	// does not bind against the Pod IP.
	ListenLocal bool `json:"listenLocal,omitempty"`
	// QueryEndpoints defines Thanos querier endpoints from which to query metrics.
	// Maps to the --query flag of thanos ruler.
	QueryEndpoints []string `json:"queryEndpoints"`
	// Define configuration for connecting to thanos query instances.
	// If this is defined, the QueryEndpoints field will be ignored.
	// Maps to the `query.config` CLI argument.
	// Only available with thanos v0.11.0 and higher.
	QueryConfig *corev1.SecretKeySelector `json:"queryConfig,omitempty"`
	// Define URLs to send alerts to Alertmanager.  For Thanos v0.10.0 and higher,
	// AlertManagersConfig should be used instead.  Note: this field will be ignored
	// if AlertManagersConfig is specified.
	// Maps to the `alertmanagers.url` arg.
	AlertManagersURL []string `json:"alertmanagersUrl"`
	// Define configuration for connecting to alertmanager.  Only available with thanos v0.10.0
	// and higher.  Maps to the `alertmanagers.config` arg.
	AlertManagersConfig *corev1.SecretKeySelector `json:"alertmanagersConfig,omitempty"`
	// A label selector to select which PrometheusRules to mount for alerting and
	// recording.
	RuleSelector *metav1.LabelSelector `json:"ruleSelector,omitempty"`
	// Namespaces to be selected for Rules discovery. If unspecified, only
	// the same namespace as the ThanosRuler object is in is used.
	RuleNamespaceSelector *metav1.LabelSelector `json:"ruleNamespaceSelector,omitempty"`
	// EnforcedNamespaceLabel enforces adding a namespace label of origin for each alert
	// and metric that is user created. The label value will always be the namespace of the object that is
	// being created.
	EnforcedNamespaceLabel string `json:"enforcedNamespaceLabel,omitempty"`
	// List of references to PrometheusRule objects
	// to be excluded from enforcing a namespace label of origin.
	// Applies only if enforcedNamespaceLabel set to true.
	ExcludedFromEnforcement []ObjectReference `json:"excludedFromEnforcement"`
	// PrometheusRulesExcludedFromEnforce - list of Prometheus rules to be excluded from enforcing
	// of adding namespace labels. Works only if enforcedNamespaceLabel set to true.
	// Make sure both ruleNamespace and ruleName are set for each pair
	// Deprecated: use excludedFromEnforcement instead.
	PrometheusRulesExcludedFromEnforce []PrometheusRuleExcludeConfig `json:"prometheusRulesExcludedFromEnforce"`
	// Log level for ThanosRuler to be configured with.
	LogLevel string `json:"logLevel,omitempty"`
	// Log format for ThanosRuler to be configured with.
	LogFormat string `json:"logFormat,omitempty"`
	// Port name used for the pods and governing service.
	// This defaults to web
	PortName string `json:"portName,omitempty"`
	// Interval between consecutive evaluations.
	EvaluationInterval string `json:"evaluationInterval"`
	// Time duration ThanosRuler shall retain data for. Default is '24h',
	// and must match the regular expression `[0-9]+(ms|s|m|h|d|w|y)` (milliseconds seconds minutes hours days weeks years).
	Retention string `json:"retention"`
	// Containers allows injecting additional containers or modifying operator generated
	// containers. This can be used to allow adding an authentication proxy to a ThanosRuler pod or
	// to change the behavior of an operator generated container. Containers described here modify
	// an operator generated container if they share the same name and modifications are done via a
	// strategic merge patch. The current container names are: `thanos-ruler` and `config-reloader`.
	// Overriding containers is entirely outside the scope of what the maintainers will support and by doing
	// so, you accept that this behaviour may break at any time without notice.
	Containers []corev1.Container `json:"containers"`
	// InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
	// fetch secrets for injection into the ThanosRuler configuration from external sources. Any
	// errors during the execution of an initContainer will lead to a restart of the Pod.
	// More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
	// Using initContainers for any use case other then secret fetching is entirely outside the scope
	// of what the maintainers will support and by doing so, you accept that this behaviour may break
	// at any time without notice.
	InitContainers []corev1.Container `json:"initContainers"`
	// TracingConfig configures tracing in Thanos. This is an experimental feature, it may change in any upcoming release in a breaking way.
	TracingConfig *corev1.SecretKeySelector `json:"tracingConfig,omitempty"`
	// TracingConfig specifies the path of the tracing configuration file.
	// When used alongside with TracingConfig, TracingConfigFile takes precedence.
	TracingConfigFile string `json:"tracingConfigFile,omitempty"`
	// Labels configure the external label pairs to ThanosRuler. A default replica label
	// `thanos_ruler_replica` will be always added  as a label with the value of the pod's name and it will be dropped in the alerts.
	Labels map[string]string `json:"labels,omitempty"`
	// AlertDropLabels configure the label names which should be dropped in ThanosRuler alerts.
	// The replica label `thanos_ruler_replica` will always be dropped in alerts.
	AlertDropLabels []string `json:"alertDropLabels"`
	// The external URL the Thanos Ruler instances will be available under. This is
	// necessary to generate correct URLs. This is necessary if Thanos Ruler is not
	// served from root of a DNS name.
	ExternalPrefix string `json:"externalPrefix,omitempty"`
	// The route prefix ThanosRuler registers HTTP handlers for. This allows thanos UI to be served on a sub-path.
	RoutePrefix string `json:"routePrefix,omitempty"`
	// GRPCServerTLSConfig configures the gRPC server from which Thanos Querier reads
	// recorded rule data.
	// Note: Currently only the CAFile, CertFile, and KeyFile fields are supported.
	// Maps to the '--grpc-server-tls-*' CLI args.
	GRPCServerTLSConfig *TLSConfig `json:"grpcServerTlsConfig,omitempty"`
	// The external Query URL the Thanos Ruler will set in the 'Source' field
	// of all alerts.
	// Maps to the '--alert.query-url' CLI arg.
	AlertQueryURL string `json:"alertQueryUrl,omitempty"`
	// Minimum number of seconds for which a newly created pod should be ready
	// without any of its container crashing for it to be considered available.
	// Defaults to 0 (pod will be considered available as soon as it is ready)
	// This is an alpha field and requires enabling StatefulSetMinReadySeconds feature gate.
	MinReadySeconds uint32 `json:"minReadySeconds,omitempty"`
	// AlertRelabelConfigs configures alert relabeling in ThanosRuler.
	// Alert relabel configurations must have the form as specified in the official Prometheus documentation:
	// https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alert_relabel_configs
	// Alternative to AlertRelabelConfigFile, and lower order priority.
	AlertRelabelConfigs *corev1.SecretKeySelector `json:"alertRelabelConfigs,omitempty"`
	// AlertRelabelConfigFile specifies the path of the alert relabeling configuration file.
	// When used alongside with AlertRelabelConfigs, alertRelabelConfigFile takes precedence.
	AlertRelabelConfigFile string `json:"alertRelabelConfigFile,omitempty"`
	// Pods' hostAliases configuration
	HostAliases []HostAlias `json:"hostAliases"`
}

func (in *ThanosRulerSpec) DeepCopyInto(out *ThanosRulerSpec) {
	*out = *in
	if in.PodMetadata != nil {
		in, out := &in.PodMetadata, &out.PodMetadata
		*out = new(EmbeddedObjectMetadata)
		(*in).DeepCopyInto(*out)
	}
	if in.ImagePullSecrets != nil {
		l := make([]corev1.LocalObjectReference, len(in.ImagePullSecrets))
		for i := range in.ImagePullSecrets {
			in.ImagePullSecrets[i].DeepCopyInto(&l[i])
		}
		out.ImagePullSecrets = l
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(corev1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	if in.Affinity != nil {
		in, out := &in.Affinity, &out.Affinity
		*out = new(corev1.Affinity)
		(*in).DeepCopyInto(*out)
	}
	if in.Tolerations != nil {
		l := make([]corev1.Toleration, len(in.Tolerations))
		for i := range in.Tolerations {
			in.Tolerations[i].DeepCopyInto(&l[i])
		}
		out.Tolerations = l
	}
	if in.TopologySpreadConstraints != nil {
		l := make([]corev1.TopologySpreadConstraint, len(in.TopologySpreadConstraints))
		for i := range in.TopologySpreadConstraints {
			in.TopologySpreadConstraints[i].DeepCopyInto(&l[i])
		}
		out.TopologySpreadConstraints = l
	}
	if in.SecurityContext != nil {
		in, out := &in.SecurityContext, &out.SecurityContext
		*out = new(corev1.PodSecurityContext)
		(*in).DeepCopyInto(*out)
	}
	if in.Storage != nil {
		in, out := &in.Storage, &out.Storage
		*out = new(StorageSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Volumes != nil {
		l := make([]corev1.Volume, len(in.Volumes))
		for i := range in.Volumes {
			in.Volumes[i].DeepCopyInto(&l[i])
		}
		out.Volumes = l
	}
	if in.ObjectStorageConfig != nil {
		in, out := &in.ObjectStorageConfig, &out.ObjectStorageConfig
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.QueryEndpoints != nil {
		t := make([]string, len(in.QueryEndpoints))
		copy(t, in.QueryEndpoints)
		out.QueryEndpoints = t
	}
	if in.QueryConfig != nil {
		in, out := &in.QueryConfig, &out.QueryConfig
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.AlertManagersURL != nil {
		t := make([]string, len(in.AlertManagersURL))
		copy(t, in.AlertManagersURL)
		out.AlertManagersURL = t
	}
	if in.AlertManagersConfig != nil {
		in, out := &in.AlertManagersConfig, &out.AlertManagersConfig
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.RuleSelector != nil {
		in, out := &in.RuleSelector, &out.RuleSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.RuleNamespaceSelector != nil {
		in, out := &in.RuleNamespaceSelector, &out.RuleNamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ExcludedFromEnforcement != nil {
		l := make([]ObjectReference, len(in.ExcludedFromEnforcement))
		for i := range in.ExcludedFromEnforcement {
			in.ExcludedFromEnforcement[i].DeepCopyInto(&l[i])
		}
		out.ExcludedFromEnforcement = l
	}
	if in.PrometheusRulesExcludedFromEnforce != nil {
		l := make([]PrometheusRuleExcludeConfig, len(in.PrometheusRulesExcludedFromEnforce))
		for i := range in.PrometheusRulesExcludedFromEnforce {
			in.PrometheusRulesExcludedFromEnforce[i].DeepCopyInto(&l[i])
		}
		out.PrometheusRulesExcludedFromEnforce = l
	}
	if in.Containers != nil {
		l := make([]corev1.Container, len(in.Containers))
		for i := range in.Containers {
			in.Containers[i].DeepCopyInto(&l[i])
		}
		out.Containers = l
	}
	if in.InitContainers != nil {
		l := make([]corev1.Container, len(in.InitContainers))
		for i := range in.InitContainers {
			in.InitContainers[i].DeepCopyInto(&l[i])
		}
		out.InitContainers = l
	}
	if in.TracingConfig != nil {
		in, out := &in.TracingConfig, &out.TracingConfig
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.AlertDropLabels != nil {
		t := make([]string, len(in.AlertDropLabels))
		copy(t, in.AlertDropLabels)
		out.AlertDropLabels = t
	}
	if in.GRPCServerTLSConfig != nil {
		in, out := &in.GRPCServerTLSConfig, &out.GRPCServerTLSConfig
		*out = new(TLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.AlertRelabelConfigs != nil {
		in, out := &in.AlertRelabelConfigs, &out.AlertRelabelConfigs
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.HostAliases != nil {
		l := make([]HostAlias, len(in.HostAliases))
		for i := range in.HostAliases {
			in.HostAliases[i].DeepCopyInto(&l[i])
		}
		out.HostAliases = l
	}
}

func (in *ThanosRulerSpec) DeepCopy() *ThanosRulerSpec {
	if in == nil {
		return nil
	}
	out := new(ThanosRulerSpec)
	in.DeepCopyInto(out)
	return out
}

type ThanosRulerStatus struct {
	// Represents whether any actions on the underlying managed objects are
	// being performed. Only delete actions will be performed.
	Paused bool `json:"paused"`
	// Total number of non-terminated pods targeted by this ThanosRuler deployment
	// (their labels match the selector).
	Replicas int `json:"replicas"`
	// Total number of non-terminated pods targeted by this ThanosRuler deployment
	// that have the desired version spec.
	UpdatedReplicas int `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this ThanosRuler deployment.
	AvailableReplicas int `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this ThanosRuler deployment.
	UnavailableReplicas int `json:"unavailableReplicas"`
}

func (in *ThanosRulerStatus) DeepCopyInto(out *ThanosRulerStatus) {
	*out = *in
}

func (in *ThanosRulerStatus) DeepCopy() *ThanosRulerStatus {
	if in == nil {
		return nil
	}
	out := new(ThanosRulerStatus)
	in.DeepCopyInto(out)
	return out
}

type EmbeddedObjectMetadata struct {
	// Name must be unique within a namespace. Is required when creating resources, although
	// some resources may allow a client to request the generation of an appropriate name
	// automatically. Name is primarily intended for creation idempotence and configuration
	// definition.
	// Cannot be updated.
	// More info: http://kubernetes.io/docs/user-guide/identifiers#names
	Name string `json:"name,omitempty"`
	// Map of string keys and values that can be used to organize and categorize
	// (scope and select) objects. May match selectors of replication controllers
	// and services.
	// More info: http://kubernetes.io/docs/user-guide/labels
	Labels map[string]string `json:"labels,omitempty"`
	// Annotations is an unstructured key value map stored with a resource that may be
	// set by external tools to store and retrieve arbitrary metadata. They are not
	// queryable and should be preserved when modifying objects.
	// More info: http://kubernetes.io/docs/user-guide/annotations
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (in *EmbeddedObjectMetadata) DeepCopyInto(out *EmbeddedObjectMetadata) {
	*out = *in
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
}

func (in *EmbeddedObjectMetadata) DeepCopy() *EmbeddedObjectMetadata {
	if in == nil {
		return nil
	}
	out := new(EmbeddedObjectMetadata)
	in.DeepCopyInto(out)
	return out
}

type StorageSpec struct {
	// Deprecated: subPath usage will be disabled by default in a future release, this option will become unnecessary.
	// DisableMountSubPath allows to remove any subPath usage in volume mounts.
	DisableMountSubPath bool `json:"disableMountSubPath,omitempty"`
	// EmptyDirVolumeSource to be used by the Prometheus StatefulSets. If specified, used in place of any volumeClaimTemplate. More
	// info: https://kubernetes.io/docs/concepts/storage/volumes/#emptydir
	EmptyDir *corev1.EmptyDirVolumeSource `json:"emptyDir,omitempty"`
	// EphemeralVolumeSource to be used by the Prometheus StatefulSets.
	// This is a beta field in k8s 1.21, for lower versions, starting with k8s 1.19, it requires enabling the GenericEphemeralVolume feature gate.
	// More info: https://kubernetes.io/docs/concepts/storage/ephemeral-volumes/#generic-ephemeral-volumes
	Ephemeral *corev1.EphemeralVolumeSource `json:"ephemeral,omitempty"`
	// A PVC spec to be used by the Prometheus StatefulSets.
	VolumeClaimTemplate *EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

func (in *StorageSpec) DeepCopyInto(out *StorageSpec) {
	*out = *in
	if in.EmptyDir != nil {
		in, out := &in.EmptyDir, &out.EmptyDir
		*out = new(corev1.EmptyDirVolumeSource)
		(*in).DeepCopyInto(*out)
	}
	if in.Ephemeral != nil {
		in, out := &in.Ephemeral, &out.Ephemeral
		*out = new(corev1.EphemeralVolumeSource)
		(*in).DeepCopyInto(*out)
	}
	if in.VolumeClaimTemplate != nil {
		in, out := &in.VolumeClaimTemplate, &out.VolumeClaimTemplate
		*out = new(EmbeddedPersistentVolumeClaim)
		(*in).DeepCopyInto(*out)
	}
}

func (in *StorageSpec) DeepCopy() *StorageSpec {
	if in == nil {
		return nil
	}
	out := new(StorageSpec)
	in.DeepCopyInto(out)
	return out
}

type HostAlias struct {
	// IP address of the host file entry.
	IP string `json:"ip"`
	// Hostnames for the above IP address.
	Hostnames []string `json:"hostnames"`
}

func (in *HostAlias) DeepCopyInto(out *HostAlias) {
	*out = *in
	if in.Hostnames != nil {
		t := make([]string, len(in.Hostnames))
		copy(t, in.Hostnames)
		out.Hostnames = t
	}
}

func (in *HostAlias) DeepCopy() *HostAlias {
	if in == nil {
		return nil
	}
	out := new(HostAlias)
	in.DeepCopyInto(out)
	return out
}

type AlertmanagerWebSpec struct {
	WebConfigFileFields `json:",inline"`
}

func (in *AlertmanagerWebSpec) DeepCopyInto(out *AlertmanagerWebSpec) {
	*out = *in
	out.WebConfigFileFields = in.WebConfigFileFields
}

func (in *AlertmanagerWebSpec) DeepCopy() *AlertmanagerWebSpec {
	if in == nil {
		return nil
	}
	out := new(AlertmanagerWebSpec)
	in.DeepCopyInto(out)
	return out
}

type AlertmanagerConfiguration struct {
	// The name of the AlertmanagerConfig resource which is used to generate the Alertmanager configuration.
	// It must be defined in the same namespace as the Alertmanager object.
	// The operator will not enforce a `namespace` label for routes and inhibition rules.
	Name string `json:"name,omitempty"`
	// Defines the global parameters of the Alertmanager configuration.
	Global *AlertmanagerGlobalConfig `json:"global,omitempty"`
}

func (in *AlertmanagerConfiguration) DeepCopyInto(out *AlertmanagerConfiguration) {
	*out = *in
	if in.Global != nil {
		in, out := &in.Global, &out.Global
		*out = new(AlertmanagerGlobalConfig)
		(*in).DeepCopyInto(*out)
	}
}

func (in *AlertmanagerConfiguration) DeepCopy() *AlertmanagerConfiguration {
	if in == nil {
		return nil
	}
	out := new(AlertmanagerConfiguration)
	in.DeepCopyInto(out)
	return out
}

type PodMetricsEndpoint struct {
	// Name of the pod port this endpoint refers to. Mutually exclusive with targetPort.
	Port string `json:"port,omitempty"`
	// Deprecated: Use 'port' instead.
	TargetPort *utilintstr.IntOrString `json:"targetPort,omitempty"`
	// HTTP path to scrape for metrics.
	// If empty, Prometheus uses the default value (e.g. `/metrics`).
	Path string `json:"path,omitempty"`
	// HTTP scheme to use for scraping.
	Scheme string `json:"scheme,omitempty"`
	// Optional HTTP URL parameters
	// This field can not be represented by protobuf.
	// map<string, > params = 5 [(dev.f110.kubeproto.field) = {go_name: "Params", api_field_name: "params", inline: false}];
	// Interval at which metrics should be scraped
	// If not specified Prometheus' global scrape interval is used.
	Interval string `json:"interval"`
	// Timeout after which the scrape is ended
	// If not specified, the Prometheus global scrape interval is used.
	ScrapeTimeout string `json:"scrapeTimeout"`
	// TLS configuration to use when scraping the endpoint.
	TLSConfig *PodMetricsEndpointTLSConfig `json:"tlsConfig,omitempty"`
	// Secret to mount to read bearer token for scraping targets. The secret
	// needs to be in the same namespace as the pod monitor and accessible by
	// the Prometheus Operator.
	BearerTokenSecret *corev1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// HonorLabels chooses the metric's labels on collisions with target labels.
	HonorLabels bool `json:"honorLabels,omitempty"`
	// HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
	HonorTimestamps bool `json:"honorTimestamps,omitempty"`
	// BasicAuth allow an endpoint to authenticate over basic authentication.
	// More info: https://prometheus.io/docs/operating/configuration/#endpoint
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Oauth2 for the URL. Only valid in Prometheus versions 2.27.0 and newer.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// Authorization section for this endpoint
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// MetricRelabelConfigs to apply to samples before ingestion.
	MetricRelabelConfigs []RelabelConfig `json:"metricRelabelings"`
	// RelabelConfigs to apply to samples before scraping.
	// Prometheus Operator automatically adds relabelings for a few standard Kubernetes fields.
	// The original scrape job's name is available via the `__tmp_prometheus_job_name` label.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []RelabelConfig `json:"relabelings"`
	// ProxyURL eg http://proxyserver:2195 Directs scrapes to proxy through this endpoint.
	ProxyURL string `json:"proxyUrl,omitempty"`
	// FollowRedirects configures whether scrape requests follow HTTP 3xx redirects.
	FollowRedirects bool `json:"followRedirects,omitempty"`
	// Whether to enable HTTP2.
	EnableHttp2 bool `json:"enableHttp2,omitempty"`
}

func (in *PodMetricsEndpoint) DeepCopyInto(out *PodMetricsEndpoint) {
	*out = *in
	if in.TargetPort != nil {
		in, out := &in.TargetPort, &out.TargetPort
		*out = new(utilintstr.IntOrString)
		*out = *in
	}
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(PodMetricsEndpointTLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.BearerTokenSecret != nil {
		in, out := &in.BearerTokenSecret, &out.BearerTokenSecret
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.OAuth2 != nil {
		in, out := &in.OAuth2, &out.OAuth2
		*out = new(OAuth2)
		(*in).DeepCopyInto(*out)
	}
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(SafeAuthorization)
		(*in).DeepCopyInto(*out)
	}
	if in.MetricRelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.MetricRelabelConfigs))
		for i := range in.MetricRelabelConfigs {
			in.MetricRelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.MetricRelabelConfigs = l
	}
	if in.RelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.RelabelConfigs))
		for i := range in.RelabelConfigs {
			in.RelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.RelabelConfigs = l
	}
}

func (in *PodMetricsEndpoint) DeepCopy() *PodMetricsEndpoint {
	if in == nil {
		return nil
	}
	out := new(PodMetricsEndpoint)
	in.DeepCopyInto(out)
	return out
}

type NamespaceSelector struct {
	// Boolean describing whether all namespaces are selected in contrast to a
	// list restricting them.
	Any bool `json:"any,omitempty"`
	// List of namespace names to select from.
	MatchNames []string `json:"matchNames"`
}

func (in *NamespaceSelector) DeepCopyInto(out *NamespaceSelector) {
	*out = *in
	if in.MatchNames != nil {
		t := make([]string, len(in.MatchNames))
		copy(t, in.MatchNames)
		out.MatchNames = t
	}
}

func (in *NamespaceSelector) DeepCopy() *NamespaceSelector {
	if in == nil {
		return nil
	}
	out := new(NamespaceSelector)
	in.DeepCopyInto(out)
	return out
}

type AttachMetadata struct {
	// When set to true, Prometheus must have permissions to get Nodes.
	Node bool `json:"node,omitempty"`
}

func (in *AttachMetadata) DeepCopyInto(out *AttachMetadata) {
	*out = *in
}

func (in *AttachMetadata) DeepCopy() *AttachMetadata {
	if in == nil {
		return nil
	}
	out := new(AttachMetadata)
	in.DeepCopyInto(out)
	return out
}

type ProberSpec struct {
	// Mandatory URL of the prober.
	URL string `json:"url"`
	// HTTP scheme to use for scraping.
	// Defaults to `http`.
	Scheme string `json:"scheme,omitempty"`
	// Path to collect metrics from.
	// Defaults to `/probe`.
	Path string `json:"path,omitempty"`
	// Optional ProxyURL.
	ProxyURL string `json:"proxyUrl,omitempty"`
}

func (in *ProberSpec) DeepCopyInto(out *ProberSpec) {
	*out = *in
}

func (in *ProberSpec) DeepCopy() *ProberSpec {
	if in == nil {
		return nil
	}
	out := new(ProberSpec)
	in.DeepCopyInto(out)
	return out
}

type ProbeTargets struct {
	// staticConfig defines the static list of targets to probe and the
	// relabeling configuration.
	// If `ingress` is also defined, `staticConfig` takes precedence.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#static_config.
	StaticConfig *ProbeTargetStaticConfig `json:"staticConfig,omitempty"`
	// ingress defines the Ingress objects to probe and the relabeling
	// configuration.
	// If `staticConfig` is also defined, `staticConfig` takes precedence.
	Ingress *ProbeTargetIngress `json:"ingress,omitempty"`
}

func (in *ProbeTargets) DeepCopyInto(out *ProbeTargets) {
	*out = *in
	if in.StaticConfig != nil {
		in, out := &in.StaticConfig, &out.StaticConfig
		*out = new(ProbeTargetStaticConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = new(ProbeTargetIngress)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ProbeTargets) DeepCopy() *ProbeTargets {
	if in == nil {
		return nil
	}
	out := new(ProbeTargets)
	in.DeepCopyInto(out)
	return out
}

type ProbeTLSConfig struct {
	SafeTLSConfig `json:",inline"`
}

func (in *ProbeTLSConfig) DeepCopyInto(out *ProbeTLSConfig) {
	*out = *in
	out.SafeTLSConfig = in.SafeTLSConfig
}

func (in *ProbeTLSConfig) DeepCopy() *ProbeTLSConfig {
	if in == nil {
		return nil
	}
	out := new(ProbeTLSConfig)
	in.DeepCopyInto(out)
	return out
}

type BasicAuth struct {
	// The secret in the service monitor namespace that contains the username
	// for authentication.
	Username *corev1.SecretKeySelector `json:"username,omitempty"`
	// The secret in the service monitor namespace that contains the password
	// for authentication.
	Password *corev1.SecretKeySelector `json:"password,omitempty"`
}

func (in *BasicAuth) DeepCopyInto(out *BasicAuth) {
	*out = *in
	if in.Username != nil {
		in, out := &in.Username, &out.Username
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Password != nil {
		in, out := &in.Password, &out.Password
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BasicAuth) DeepCopy() *BasicAuth {
	if in == nil {
		return nil
	}
	out := new(BasicAuth)
	in.DeepCopyInto(out)
	return out
}

type OAuth2 struct {
	// The secret or configmap containing the OAuth2 client id
	ClientID SecretOrConfigMap `json:"clientId"`
	// The secret containing the OAuth2 client secret
	ClientSecret corev1.SecretKeySelector `json:"clientSecret"`
	// The URL to fetch the token from
	TokenURL string `json:"tokenUrl"`
	// OAuth2 scopes used for the token request
	Scopes []string `json:"scopes"`
	// Parameters to append to the token URL
	EndpointParams map[string]string `json:"endpointParams,omitempty"`
}

func (in *OAuth2) DeepCopyInto(out *OAuth2) {
	*out = *in
	in.ClientID.DeepCopyInto(&out.ClientID)
	in.ClientSecret.DeepCopyInto(&out.ClientSecret)
	if in.Scopes != nil {
		t := make([]string, len(in.Scopes))
		copy(t, in.Scopes)
		out.Scopes = t
	}
	if in.EndpointParams != nil {
		in, out := &in.EndpointParams, &out.EndpointParams
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
}

func (in *OAuth2) DeepCopy() *OAuth2 {
	if in == nil {
		return nil
	}
	out := new(OAuth2)
	in.DeepCopyInto(out)
	return out
}

type RelabelConfig struct {
	// The source labels select values from existing labels. Their content is concatenated
	// using the configured separator and matched against the configured regular expression
	// for the replace, keep, and drop actions.
	SourceLabels []string `json:"sourceLabels"`
	// Separator placed between concatenated source label values. default is ';'.
	Separator string `json:"separator,omitempty"`
	// Label to which the resulting value is written in a replace action.
	// It is mandatory for replace actions. Regex capture groups are available.
	TargetLabel string `json:"targetLabel,omitempty"`
	// Regular expression against which the extracted value is matched. Default is '(.*)'
	Regex string `json:"regex,omitempty"`
	// Modulus to take of the hash of the source label values.
	Modulus uint64 `json:"modulus,omitempty"`
	// Replacement value against which a regex replace is performed if the
	// regular expression matches. Regex capture groups are available. Default is '$1'
	Replacement string `json:"replacement,omitempty"`
	// Action to perform based on regex matching. Default is 'replace'.
	// uppercase and lowercase actions require Prometheus >= 2.36.
	Action string `json:"action,omitempty"`
}

func (in *RelabelConfig) DeepCopyInto(out *RelabelConfig) {
	*out = *in
	if in.SourceLabels != nil {
		t := make([]string, len(in.SourceLabels))
		copy(t, in.SourceLabels)
		out.SourceLabels = t
	}
}

func (in *RelabelConfig) DeepCopy() *RelabelConfig {
	if in == nil {
		return nil
	}
	out := new(RelabelConfig)
	in.DeepCopyInto(out)
	return out
}

type SafeAuthorization struct {
	// Set the authentication type. Defaults to Bearer, Basic will cause an
	// error
	Type string `json:"type,omitempty"`
	// The secret's key that contains the credentials of the request
	Credentials *corev1.SecretKeySelector `json:"credentials,omitempty"`
}

func (in *SafeAuthorization) DeepCopyInto(out *SafeAuthorization) {
	*out = *in
	if in.Credentials != nil {
		in, out := &in.Credentials, &out.Credentials
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *SafeAuthorization) DeepCopy() *SafeAuthorization {
	if in == nil {
		return nil
	}
	out := new(SafeAuthorization)
	in.DeepCopyInto(out)
	return out
}

type CommonPrometheusFields struct {
	// PodMetadata configures Labels and Annotations which are propagated to the prometheus pods.
	PodMetadata *EmbeddedObjectMetadata `json:"podMetadata,omitempty"`
	// ServiceMonitors to be selected for target discovery. *Deprecated:* if
	// neither this nor podMonitorSelector are specified, configuration is
	// unmanaged.
	ServiceMonitorSelector *metav1.LabelSelector `json:"serviceMonitorSelector,omitempty"`
	// Namespace's labels to match for ServiceMonitor discovery. If nil, only
	// check own namespace.
	ServiceMonitorNamespaceSelector *metav1.LabelSelector `json:"serviceMonitorNamespaceSelector,omitempty"`
	// *Experimental* PodMonitors to be selected for target discovery.
	// *Deprecated:* if neither this nor serviceMonitorSelector are specified,
	// configuration is unmanaged.
	PodMonitorSelector *metav1.LabelSelector `json:"podMonitorSelector,omitempty"`
	// Namespace's labels to match for PodMonitor discovery. If nil, only
	// check own namespace.
	PodMonitorNamespaceSelector *metav1.LabelSelector `json:"podMonitorNamespaceSelector,omitempty"`
	// *Experimental* Probes to be selected for target discovery.
	ProbeSelector *metav1.LabelSelector `json:"probeSelector,omitempty"`
	// *Experimental* Namespaces to be selected for Probe discovery. If nil, only check own namespace.
	ProbeNamespaceSelector *metav1.LabelSelector `json:"probeNamespaceSelector,omitempty"`
	// Version of Prometheus to be deployed.
	Version string `json:"version,omitempty"`
	// When a Prometheus deployment is paused, no actions except for deletion
	// will be performed on the underlying objects.
	Paused bool `json:"paused,omitempty"`
	// Image if specified has precedence over baseImage, tag and sha
	// combinations. Specifying the version is still necessary to ensure the
	// Prometheus Operator knows what version of Prometheus is being
	// configured.
	Image string `json:"image,omitempty"`
	// An optional list of references to secrets in the same namespace
	// to use for pulling prometheus and alertmanager images from registries
	// see http://kubernetes.io/docs/user-guide/images#specifying-imagepullsecrets-on-a-pod
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets"`
	// Number of replicas of each shard to deploy for a Prometheus deployment.
	// Number of replicas multiplied by shards is the total number of Pods
	// created.
	Replicas int `json:"replicas,omitempty"`
	// EXPERIMENTAL: Number of shards to distribute targets onto. Number of
	// replicas multiplied by shards is the total number of Pods created. Note
	// that scaling down shards will not reshard data onto remaining instances,
	// it must be manually moved. Increasing shards will not reshard data
	// either but it will continue to be available from the same instances. To
	// query globally use Thanos sidecar and Thanos querier or remote write
	// data to a central location. Sharding is done on the content of the
	// `__address__` target meta-label.
	Shards int `json:"shards,omitempty"`
	// Name of Prometheus external label used to denote replica name.
	// Defaults to the value of `prometheus_replica`. External label will
	// _not_ be added when value is set to empty string (`""`).
	ReplicaExternalLabelName string `json:"replicaExternalLabelName,omitempty"`
	// Name of Prometheus external label used to denote Prometheus instance
	// name. Defaults to the value of `prometheus`. External label will
	// _not_ be added when value is set to empty string (`""`).
	PrometheusExternalLabelName string `json:"prometheusExternalLabelName,omitempty"`
	// Log level for Prometheus to be configured with.
	LogLevel string `json:"logLevel,omitempty"`
	// Log format for Prometheus to be configured with.
	LogFormat string `json:"logFormat,omitempty"`
	// Interval between consecutive scrapes. Default: `30s`
	ScrapeInterval string `json:"scrapeInterval"`
	// Number of seconds to wait for target to respond before erroring.
	ScrapeTimeout string `json:"scrapeTimeout"`
	// The labels to add to any time series or alerts when communicating with
	// external systems (federation, remote storage, Alertmanager).
	ExternalLabels map[string]string `json:"externalLabels,omitempty"`
	// Enable Prometheus to be used as a receiver for the Prometheus remote write protocol. Defaults to the value of `false`.
	// WARNING: This is not considered an efficient way of ingesting samples.
	// Use it with caution for specific low-volume use cases.
	// It is not suitable for replacing the ingestion via scraping and turning
	// Prometheus into a push-based metrics collection system.
	// For more information see https://prometheus.io/docs/prometheus/latest/querying/api/#remote-write-receiver
	// Only valid in Prometheus versions 2.33.0 and newer.
	EnableRemoteWriteReceiver bool `json:"enableRemoteWriteReceiver,omitempty"`
	// Enable access to Prometheus disabled features. By default, no features are enabled.
	// Enabling disabled features is entirely outside the scope of what the maintainers will
	// support and by doing so, you accept that this behaviour may break at any
	// time without notice.
	// For more information see https://prometheus.io/docs/prometheus/latest/disabled_features/
	EnableFeatures []string `json:"enableFeatures"`
	// The external URL the Prometheus instances will be available under. This is
	// necessary to generate correct URLs. This is necessary if Prometheus is not
	// served from root of a DNS name.
	ExternalURL string `json:"externalUrl,omitempty"`
	// The route prefix Prometheus registers HTTP handlers for. This is useful,
	// if using ExternalURL and a proxy is rewriting HTTP routes of a request,
	// and the actual ExternalURL is still true, but the server serves requests
	// under a different route prefix. For example for use with `kubectl proxy`.
	RoutePrefix string `json:"routePrefix,omitempty"`
	// Storage spec to specify how storage shall be used.
	Storage *StorageSpec `json:"storage,omitempty"`
	// Volumes allows configuration of additional volumes on the output StatefulSet definition. Volumes specified will
	// be appended to other volumes that are generated as a result of StorageSpec objects.
	Volumes []corev1.Volume `json:"volumes"`
	// VolumeMounts allows configuration of additional VolumeMounts on the output StatefulSet definition.
	// VolumeMounts specified will be appended to other VolumeMounts in the prometheus container,
	// that are generated as a result of StorageSpec objects.
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts"`
	// Defines the web command line flags when starting Prometheus.
	Web *PrometheusWebSpec `json:"web,omitempty"`
	// Define resources requests and limits for single Pods.
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// Define which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// ServiceAccountName is the name of the ServiceAccount to use to run the
	// Prometheus Pods.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Secrets is a list of Secrets in the same namespace as the Prometheus
	// object, which shall be mounted into the Prometheus Pods.
	// The Secrets are mounted into /etc/prometheus/secrets/<secret-name>.
	Secrets []string `json:"secrets"`
	// ConfigMaps is a list of ConfigMaps in the same namespace as the Prometheus
	// object, which shall be mounted into the Prometheus Pods.
	// The ConfigMaps are mounted into /etc/prometheus/configmaps/<configmap-name>.
	ConfigMaps []string `json:"configMaps"`
	// If specified, the pod's scheduling constraints.
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// If specified, the pod's tolerations.
	Tolerations []corev1.Toleration `json:"tolerations"`
	// If specified, the pod's topology spread constraints.
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints"`
	// remoteWrite is the list of remote write configurations.
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite"`
	// SecurityContext holds pod-level security attributes and common container settings.
	// This defaults to the default PodSecurityContext.
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`
	// ListenLocal makes the Prometheus server listen on loopback, so that it
	// does not bind against the Pod IP.
	ListenLocal bool `json:"listenLocal,omitempty"`
	// Containers allows injecting additional containers or modifying operator
	// generated containers. This can be used to allow adding an authentication
	// proxy to a Prometheus pod or to change the behavior of an operator
	// generated container. Containers described here modify an operator
	// generated container if they share the same name and modifications are
	// done via a strategic merge patch. The current container names are:
	// `prometheus`, `config-reloader`, and `thanos-sidecar`. Overriding
	// containers is entirely outside the scope of what the maintainers will
	// support and by doing so, you accept that this behaviour may break at any
	// time without notice.
	Containers []corev1.Container `json:"containers"`
	// InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
	// fetch secrets for injection into the Prometheus configuration from external sources. Any errors
	// during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
	// InitContainers described here modify an operator
	// generated init containers if they share the same name and modifications are
	// done via a strategic merge patch. The current init container name is:
	// `init-config-reloader`. Overriding init containers is entirely outside the
	// scope of what the maintainers will support and by doing so, you accept that
	// this behaviour may break at any time without notice.
	InitContainers []corev1.Container `json:"initContainers"`
	// AdditionalScrapeConfigs allows specifying a key of a Secret containing
	// additional Prometheus scrape configurations. Scrape configurations
	// specified are appended to the configurations generated by the Prometheus
	// Operator. Job configurations specified must have the form as specified
	// in the official Prometheus documentation:
	// https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config.
	// As scrape configs are appended, the user is responsible to make sure it
	// is valid. Note that using this feature may expose the possibility to
	// break upgrades of Prometheus. It is advised to review Prometheus release
	// notes to ensure that no incompatible scrape configs are going to break
	// Prometheus after the upgrade.
	AdditionalScrapeConfigs *corev1.SecretKeySelector `json:"additionalScrapeConfigs,omitempty"`
	// APIServerConfig allows specifying a host and auth methods to access apiserver.
	// If left empty, Prometheus is assumed to run inside of the cluster
	// and will discover API servers automatically and use the pod's CA certificate
	// and bearer token file at /var/run/secrets/kubernetes.io/serviceaccount/.
	APIServerConfig *APIServerConfig `json:"apiserverConfig,omitempty"`
	// Priority class assigned to the Pods
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// Port name used for the pods and governing service.
	// This defaults to web
	PortName string `json:"portName,omitempty"`
	// ArbitraryFSAccessThroughSMs configures whether configuration
	// based on a service monitor can access arbitrary files on the file system
	// of the Prometheus container e.g. bearer token files.
	ArbitraryFSAccessThroughSMs *ArbitraryFSAccessThroughSMsConfig `json:"arbitraryFSAccessThroughSMs,omitempty"`
	// When true, Prometheus resolves label conflicts by renaming the labels in
	// the scraped data to "exported_<label value>" for all targets created
	// from service and pod monitors.
	// Otherwise the HonorLabels field of the service or pod monitor applies.
	OverrideHonorLabels bool `json:"overrideHonorLabels,omitempty"`
	// When true, Prometheus ignores the timestamps for all the targets created
	// from service and pod monitors.
	// Otherwise the HonorTimestamps field of the service or pod monitor applies.
	OverrideHonorTimestamps bool `json:"overrideHonorTimestamps,omitempty"`
	// IgnoreNamespaceSelectors if set to true will ignore NamespaceSelector
	// settings from all PodMonitor, ServiceMonitor and Probe objects. They will
	// only discover endpoints within the namespace of the PodMonitor,
	// ServiceMonitor and Probe objects.
	// Defaults to false.
	IgnoreNamespaceSelectors bool `json:"ignoreNamespaceSelectors,omitempty"`
	// EnforcedNamespaceLabel If set, a label will be added to
	// 1. all user-metrics (created by `ServiceMonitor`, `PodMonitor` and `Probe` objects) and
	// 2. in all `PrometheusRule` objects (except the ones excluded in `prometheusRulesExcludedFromEnforce`) to
	// * alerting & recording rules and
	// * the metrics used in their expressions (`expr`).
	// Label name is this field's value.
	// Label value is the namespace of the created object (mentioned above).
	EnforcedNamespaceLabel string `json:"enforcedNamespaceLabel,omitempty"`
	// EnforcedSampleLimit defines global limit on number of scraped samples
	// that will be accepted. This overrides any SampleLimit set per
	// ServiceMonitor or/and PodMonitor. It is meant to be used by admins to
	// enforce the SampleLimit to keep overall number of samples/series under
	// the desired limit.
	// Note that if SampleLimit is lower that value will be taken instead.
	EnforcedSampleLimit uint64 `json:"enforcedSampleLimit,omitempty"`
	// EnforcedTargetLimit defines a global limit on the number of scraped
	// targets.  This overrides any TargetLimit set per ServiceMonitor or/and
	// PodMonitor.  It is meant to be used by admins to enforce the TargetLimit
	// to keep the overall number of targets under the desired limit.
	// Note that if TargetLimit is lower, that value will be taken instead,
	// except if either value is zero, in which case the non-zero value will be
	// used.  If both values are zero, no limit is enforced.
	EnforcedTargetLimit uint64 `json:"enforcedTargetLimit,omitempty"`
	// Per-scrape limit on number of labels that will be accepted for a sample. If
	// more than this number of labels are present post metric-relabeling, the
	// entire scrape will be treated as failed. 0 means no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	EnforcedLabelLimit uint64 `json:"enforcedLabelLimit,omitempty"`
	// Per-scrape limit on length of labels name that will be accepted for a sample.
	// If a label name is longer than this number post metric-relabeling, the entire
	// scrape will be treated as failed. 0 means no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	EnforcedLabelNameLengthLimit uint64 `json:"enforcedLabelNameLengthLimit,omitempty"`
	// Per-scrape limit on length of labels value that will be accepted for a sample.
	// If a label value is longer than this number post metric-relabeling, the
	// entire scrape will be treated as failed. 0 means no limit.
	// Only valid in Prometheus versions 2.27.0 and newer.
	EnforcedLabelValueLengthLimit uint64 `json:"enforcedLabelValueLengthLimit,omitempty"`
	// EnforcedBodySizeLimit defines the maximum size of uncompressed response body
	// that will be accepted by Prometheus. Targets responding with a body larger than this many bytes
	// will cause the scrape to fail. Example: 100MB.
	// If defined, the limit will apply to all service/pod monitors and probes.
	// This is an experimental feature, this behaviour could
	// change or be removed in the future.
	// Only valid in Prometheus versions 2.28.0 and newer.
	EnforcedBodySizeLimit string `json:"enforcedBodySizeLimit"`
	// Minimum number of seconds for which a newly created pod should be ready
	// without any of its container crashing for it to be considered available.
	// Defaults to 0 (pod will be considered available as soon as it is ready)
	// This is an alpha field and requires enabling StatefulSetMinReadySeconds feature gate.
	MinReadySeconds uint32 `json:"minReadySeconds,omitempty"`
	// Pods' hostAliases configuration
	HostAliases []HostAlias `json:"hostAliases"`
	// AdditionalArgs allows setting additional arguments for the Prometheus container.
	// It is intended for e.g. activating hidden flags which are not supported by
	// the dedicated configuration options yet. The arguments are passed as-is to the
	// Prometheus container which may cause issues if they are invalid or not supporeted
	// by the given Prometheus version.
	// In case of an argument conflict (e.g. an argument which is already set by the
	// operator itself) or when providing an invalid argument the reconciliation will
	// fail and an error will be logged.
	AdditionalArgs []Argument `json:"additionalArgs"`
	// Enable compression of the write-ahead log using Snappy. This flag is
	// only available in versions of Prometheus >= 2.11.0.
	WALCompression bool `json:"walCompression,omitempty"`
	// List of references to PodMonitor, ServiceMonitor, Probe and PrometheusRule objects
	// to be excluded from enforcing a namespace label of origin.
	// Applies only if enforcedNamespaceLabel set to true.
	ExcludedFromEnforcement []ObjectReference `json:"excludedFromEnforcement"`
}

func (in *CommonPrometheusFields) DeepCopyInto(out *CommonPrometheusFields) {
	*out = *in
	if in.PodMetadata != nil {
		in, out := &in.PodMetadata, &out.PodMetadata
		*out = new(EmbeddedObjectMetadata)
		(*in).DeepCopyInto(*out)
	}
	if in.ServiceMonitorSelector != nil {
		in, out := &in.ServiceMonitorSelector, &out.ServiceMonitorSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ServiceMonitorNamespaceSelector != nil {
		in, out := &in.ServiceMonitorNamespaceSelector, &out.ServiceMonitorNamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.PodMonitorSelector != nil {
		in, out := &in.PodMonitorSelector, &out.PodMonitorSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.PodMonitorNamespaceSelector != nil {
		in, out := &in.PodMonitorNamespaceSelector, &out.PodMonitorNamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ProbeSelector != nil {
		in, out := &in.ProbeSelector, &out.ProbeSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ProbeNamespaceSelector != nil {
		in, out := &in.ProbeNamespaceSelector, &out.ProbeNamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ImagePullSecrets != nil {
		l := make([]corev1.LocalObjectReference, len(in.ImagePullSecrets))
		for i := range in.ImagePullSecrets {
			in.ImagePullSecrets[i].DeepCopyInto(&l[i])
		}
		out.ImagePullSecrets = l
	}
	if in.ExternalLabels != nil {
		in, out := &in.ExternalLabels, &out.ExternalLabels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.EnableFeatures != nil {
		t := make([]string, len(in.EnableFeatures))
		copy(t, in.EnableFeatures)
		out.EnableFeatures = t
	}
	if in.Storage != nil {
		in, out := &in.Storage, &out.Storage
		*out = new(StorageSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Volumes != nil {
		l := make([]corev1.Volume, len(in.Volumes))
		for i := range in.Volumes {
			in.Volumes[i].DeepCopyInto(&l[i])
		}
		out.Volumes = l
	}
	if in.VolumeMounts != nil {
		l := make([]corev1.VolumeMount, len(in.VolumeMounts))
		for i := range in.VolumeMounts {
			in.VolumeMounts[i].DeepCopyInto(&l[i])
		}
		out.VolumeMounts = l
	}
	if in.Web != nil {
		in, out := &in.Web, &out.Web
		*out = new(PrometheusWebSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(corev1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Secrets != nil {
		t := make([]string, len(in.Secrets))
		copy(t, in.Secrets)
		out.Secrets = t
	}
	if in.ConfigMaps != nil {
		t := make([]string, len(in.ConfigMaps))
		copy(t, in.ConfigMaps)
		out.ConfigMaps = t
	}
	if in.Affinity != nil {
		in, out := &in.Affinity, &out.Affinity
		*out = new(corev1.Affinity)
		(*in).DeepCopyInto(*out)
	}
	if in.Tolerations != nil {
		l := make([]corev1.Toleration, len(in.Tolerations))
		for i := range in.Tolerations {
			in.Tolerations[i].DeepCopyInto(&l[i])
		}
		out.Tolerations = l
	}
	if in.TopologySpreadConstraints != nil {
		l := make([]corev1.TopologySpreadConstraint, len(in.TopologySpreadConstraints))
		for i := range in.TopologySpreadConstraints {
			in.TopologySpreadConstraints[i].DeepCopyInto(&l[i])
		}
		out.TopologySpreadConstraints = l
	}
	if in.RemoteWrite != nil {
		l := make([]RemoteWriteSpec, len(in.RemoteWrite))
		for i := range in.RemoteWrite {
			in.RemoteWrite[i].DeepCopyInto(&l[i])
		}
		out.RemoteWrite = l
	}
	if in.SecurityContext != nil {
		in, out := &in.SecurityContext, &out.SecurityContext
		*out = new(corev1.PodSecurityContext)
		(*in).DeepCopyInto(*out)
	}
	if in.Containers != nil {
		l := make([]corev1.Container, len(in.Containers))
		for i := range in.Containers {
			in.Containers[i].DeepCopyInto(&l[i])
		}
		out.Containers = l
	}
	if in.InitContainers != nil {
		l := make([]corev1.Container, len(in.InitContainers))
		for i := range in.InitContainers {
			in.InitContainers[i].DeepCopyInto(&l[i])
		}
		out.InitContainers = l
	}
	if in.AdditionalScrapeConfigs != nil {
		in, out := &in.AdditionalScrapeConfigs, &out.AdditionalScrapeConfigs
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.APIServerConfig != nil {
		in, out := &in.APIServerConfig, &out.APIServerConfig
		*out = new(APIServerConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.ArbitraryFSAccessThroughSMs != nil {
		in, out := &in.ArbitraryFSAccessThroughSMs, &out.ArbitraryFSAccessThroughSMs
		*out = new(ArbitraryFSAccessThroughSMsConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.HostAliases != nil {
		l := make([]HostAlias, len(in.HostAliases))
		for i := range in.HostAliases {
			in.HostAliases[i].DeepCopyInto(&l[i])
		}
		out.HostAliases = l
	}
	if in.AdditionalArgs != nil {
		l := make([]Argument, len(in.AdditionalArgs))
		for i := range in.AdditionalArgs {
			in.AdditionalArgs[i].DeepCopyInto(&l[i])
		}
		out.AdditionalArgs = l
	}
	if in.ExcludedFromEnforcement != nil {
		l := make([]ObjectReference, len(in.ExcludedFromEnforcement))
		for i := range in.ExcludedFromEnforcement {
			in.ExcludedFromEnforcement[i].DeepCopyInto(&l[i])
		}
		out.ExcludedFromEnforcement = l
	}
}

func (in *CommonPrometheusFields) DeepCopy() *CommonPrometheusFields {
	if in == nil {
		return nil
	}
	out := new(CommonPrometheusFields)
	in.DeepCopyInto(out)
	return out
}

type Rules struct {
	Alert *RulesAlert `json:"alert,omitempty"`
}

func (in *Rules) DeepCopyInto(out *Rules) {
	*out = *in
	if in.Alert != nil {
		in, out := &in.Alert, &out.Alert
		*out = new(RulesAlert)
		(*in).DeepCopyInto(*out)
	}
}

func (in *Rules) DeepCopy() *Rules {
	if in == nil {
		return nil
	}
	out := new(Rules)
	in.DeepCopyInto(out)
	return out
}

type PrometheusRuleExcludeConfig struct {
	// RuleNamespace - namespace of excluded rule
	RuleNamespace string `json:"ruleNamespace"`
	// RuleNamespace - name of excluded rule
	RuleName string `json:"ruleName"`
}

func (in *PrometheusRuleExcludeConfig) DeepCopyInto(out *PrometheusRuleExcludeConfig) {
	*out = *in
}

func (in *PrometheusRuleExcludeConfig) DeepCopy() *PrometheusRuleExcludeConfig {
	if in == nil {
		return nil
	}
	out := new(PrometheusRuleExcludeConfig)
	in.DeepCopyInto(out)
	return out
}

type QuerySpec struct {
	// The delta difference allowed for retrieving metrics during expression evaluations.
	LookbackDelta string `json:"lookbackDelta,omitempty"`
	// Number of concurrent queries that can be run at once.
	MaxConcurrency int `json:"maxConcurrency,omitempty"`
	// Maximum number of samples a single query can load into memory. Note that queries will fail if they would load more samples than this into memory, so this also limits the number of samples a query can return.
	MaxSamples int `json:"maxSamples,omitempty"`
	// Maximum time a query may take before being aborted.
	Timeout string `json:"timeout"`
}

func (in *QuerySpec) DeepCopyInto(out *QuerySpec) {
	*out = *in
}

func (in *QuerySpec) DeepCopy() *QuerySpec {
	if in == nil {
		return nil
	}
	out := new(QuerySpec)
	in.DeepCopyInto(out)
	return out
}

type AlertingSpec struct {
	// AlertmanagerEndpoints Prometheus should fire alerts against.
	Alertmanagers []AlertmanagerEndpoints `json:"alertmanagers"`
}

func (in *AlertingSpec) DeepCopyInto(out *AlertingSpec) {
	*out = *in
	if in.Alertmanagers != nil {
		l := make([]AlertmanagerEndpoints, len(in.Alertmanagers))
		for i := range in.Alertmanagers {
			in.Alertmanagers[i].DeepCopyInto(&l[i])
		}
		out.Alertmanagers = l
	}
}

func (in *AlertingSpec) DeepCopy() *AlertingSpec {
	if in == nil {
		return nil
	}
	out := new(AlertingSpec)
	in.DeepCopyInto(out)
	return out
}

type RemoteReadSpec struct {
	// The URL of the endpoint to query from.
	URL string `json:"url"`
	// The name of the remote read queue, it must be unique if specified. The name
	// is used in metrics and logging in order to differentiate read
	// configurations.  Only valid in Prometheus versions 2.15.0 and newer.
	Name string `json:"name,omitempty"`
	// An optional list of equality matchers which have to be present
	// in a selector to query the remote read endpoint.
	RequiredMatchers map[string]string `json:"requiredMatchers,omitempty"`
	// Timeout for requests to the remote read endpoint.
	RemoteTimeout string `json:"remoteTimeout"`
	// Custom HTTP headers to be sent along with each remote read request.
	// Be aware that headers that are set by Prometheus itself can't be overwritten.
	// Only valid in Prometheus versions 2.26.0 and newer.
	Headers map[string]string `json:"headers,omitempty"`
	// Whether reads should be made for queries for time ranges that
	// the local storage should have complete data for.
	ReadRecent bool `json:"readRecent,omitempty"`
	// BasicAuth for the URL.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Oauth2 for the URL. Only valid in Prometheus versions 2.27.0 and newer.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// Bearer token for remote read.
	BearerToken string `json:"bearerToken,omitempty"`
	// File to read bearer token for remote read.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Authorization section for remote read
	Authorization *Authorization `json:"authorization,omitempty"`
	// TLS Config to use for remote read.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Optional ProxyURL.
	ProxyURL string `json:"proxyUrl,omitempty"`
}

func (in *RemoteReadSpec) DeepCopyInto(out *RemoteReadSpec) {
	*out = *in
	if in.RequiredMatchers != nil {
		in, out := &in.RequiredMatchers, &out.RequiredMatchers
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Headers != nil {
		in, out := &in.Headers, &out.Headers
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.OAuth2 != nil {
		in, out := &in.OAuth2, &out.OAuth2
		*out = new(OAuth2)
		(*in).DeepCopyInto(*out)
	}
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(Authorization)
		(*in).DeepCopyInto(*out)
	}
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(TLSConfig)
		(*in).DeepCopyInto(*out)
	}
}

func (in *RemoteReadSpec) DeepCopy() *RemoteReadSpec {
	if in == nil {
		return nil
	}
	out := new(RemoteReadSpec)
	in.DeepCopyInto(out)
	return out
}

type ThanosSpec struct {
	// Image if specified has precedence over baseImage, tag and sha
	// combinations. Specifying the version is still necessary to ensure the
	// Prometheus Operator knows what version of Thanos is being
	// configured.
	Image string `json:"image,omitempty"`
	// Version describes the version of Thanos to use.
	Version string `json:"version,omitempty"`
	// Tag of Thanos sidecar container image to be deployed. Defaults to the value of `version`.
	// Version is ignored if Tag is set.
	// Deprecated: use 'image' instead.  The image tag can be specified
	// as part of the image URL.
	Tag string `json:"tag,omitempty"`
	// SHA of Thanos container image to be deployed. Defaults to the value of `version`.
	// Similar to a tag, but the SHA explicitly deploys an immutable container image.
	// Version and Tag are ignored if SHA is set.
	// Deprecated: use 'image' instead.  The image digest can be specified
	// as part of the image URL.
	SHA string `json:"sha,omitempty"`
	// Thanos base image if other than default.
	// Deprecated: use 'image' instead
	BaseImage string `json:"baseImage,omitempty"`
	// Resources defines the resource requirements for the Thanos sidecar.
	// If not provided, no requests/limits will be set
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
	// ObjectStorageConfig configures object storage in Thanos.
	// Alternative to ObjectStorageConfigFile, and lower order priority.
	ObjectStorageConfig *corev1.SecretKeySelector `json:"objectStorageConfig,omitempty"`
	// ObjectStorageConfigFile specifies the path of the object storage configuration file.
	// When used alongside with ObjectStorageConfig, ObjectStorageConfigFile takes precedence.
	ObjectStorageConfigFile string `json:"objectStorageConfigFile,omitempty"`
	// ListenLocal makes the Thanos sidecar listen on loopback, so that it
	// does not bind against the Pod IP.
	ListenLocal bool `json:"listenLocal,omitempty"`
	// TracingConfig configures tracing in Thanos. This is an experimental feature, it may change in any upcoming release in a breaking way.
	TracingConfig *corev1.SecretKeySelector `json:"tracingConfig,omitempty"`
	// TracingConfig specifies the path of the tracing configuration file.
	// When used alongside with TracingConfig, TracingConfigFile takes precedence.
	TracingConfigFile string `json:"tracingConfigFile,omitempty"`
	// GRPCServerTLSConfig configures the gRPC server from which Thanos Querier reads
	// recorded rule data.
	// Note: Currently only the CAFile, CertFile, and KeyFile fields are supported.
	// Maps to the '--grpc-server-tls-*' CLI args.
	GRPCServerTLSConfig *TLSConfig `json:"grpcServerTlsConfig,omitempty"`
	// LogLevel for Thanos sidecar to be configured with.
	LogLevel string `json:"logLevel,omitempty"`
	// LogFormat for Thanos sidecar to be configured with.
	LogFormat string `json:"logFormat,omitempty"`
	// MinTime for Thanos sidecar to be configured with. Option can be a constant time in RFC3339 format or time duration relative to current time, such as -1d or 2h45m. Valid duration units are ms, s, m, h, d, w, y.
	MinTime string `json:"minTime,omitempty"`
	// ReadyTimeout is the maximum time Thanos sidecar will wait for Prometheus to start. Eg 10m
	ReadyTimeout string `json:"readyTimeout"`
	// VolumeMounts allows configuration of additional VolumeMounts on the output StatefulSet definition.
	// VolumeMounts specified will be appended to other VolumeMounts in the thanos-sidecar container.
	VolumeMounts []corev1.VolumeMount `json:"volumeMounts"`
	// AdditionalArgs allows setting additional arguments for the Thanos container.
	// The arguments are passed as-is to the Thanos container which may cause issues
	// if they are invalid or not supporeted the given Thanos version.
	// In case of an argument conflict (e.g. an argument which is already set by the
	// operator itself) or when providing an invalid argument the reconciliation will
	// fail and an error will be logged.
	AdditionalArgs []Argument `json:"additionalArgs"`
}

func (in *ThanosSpec) DeepCopyInto(out *ThanosSpec) {
	*out = *in
	if in.Resources != nil {
		in, out := &in.Resources, &out.Resources
		*out = new(corev1.ResourceRequirements)
		(*in).DeepCopyInto(*out)
	}
	if in.ObjectStorageConfig != nil {
		in, out := &in.ObjectStorageConfig, &out.ObjectStorageConfig
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.TracingConfig != nil {
		in, out := &in.TracingConfig, &out.TracingConfig
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.GRPCServerTLSConfig != nil {
		in, out := &in.GRPCServerTLSConfig, &out.GRPCServerTLSConfig
		*out = new(TLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.VolumeMounts != nil {
		l := make([]corev1.VolumeMount, len(in.VolumeMounts))
		for i := range in.VolumeMounts {
			in.VolumeMounts[i].DeepCopyInto(&l[i])
		}
		out.VolumeMounts = l
	}
	if in.AdditionalArgs != nil {
		l := make([]Argument, len(in.AdditionalArgs))
		for i := range in.AdditionalArgs {
			in.AdditionalArgs[i].DeepCopyInto(&l[i])
		}
		out.AdditionalArgs = l
	}
}

func (in *ThanosSpec) DeepCopy() *ThanosSpec {
	if in == nil {
		return nil
	}
	out := new(ThanosSpec)
	in.DeepCopyInto(out)
	return out
}

type Exemplars struct {
	// Maximum number of exemplars stored in memory for all series.
	// If not set, Prometheus uses its default value.
	// A value of zero or less than zero disables the storage.
	MaxSize int64 `json:"maxSize,omitempty"`
}

func (in *Exemplars) DeepCopyInto(out *Exemplars) {
	*out = *in
}

func (in *Exemplars) DeepCopy() *Exemplars {
	if in == nil {
		return nil
	}
	out := new(Exemplars)
	in.DeepCopyInto(out)
	return out
}

type PrometheusCondition struct {
	// Type of the condition being reported.
	Type PrometheusConditionType `json:"type"`
	// status of the condition.
	Status PrometheusConditionStatus `json:"status"`
	// lastTransitionTime is the time of the last update to the current status property.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`
	// Reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
	// Human-readable message indicating details for the condition's last transition.
	Message string `json:"message,omitempty"`
}

func (in *PrometheusCondition) DeepCopyInto(out *PrometheusCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
}

func (in *PrometheusCondition) DeepCopy() *PrometheusCondition {
	if in == nil {
		return nil
	}
	out := new(PrometheusCondition)
	in.DeepCopyInto(out)
	return out
}

type ShardStatus struct {
	// Identifier of the shard.
	ShardID string `json:"shardID"`
	// Total number of pods targeted by this shard.
	Replicas int `json:"replicas"`
	// Total number of non-terminated pods targeted by this shard
	// that have the desired spec.
	UpdatedReplicas int `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this shard.
	AvailableReplicas int `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this shard.
	UnavailableReplicas int `json:"unavailableReplicas"`
}

func (in *ShardStatus) DeepCopyInto(out *ShardStatus) {
	*out = *in
}

func (in *ShardStatus) DeepCopy() *ShardStatus {
	if in == nil {
		return nil
	}
	out := new(ShardStatus)
	in.DeepCopyInto(out)
	return out
}

type RuleGroup struct {
	Name                    string `json:"name"`
	Interval                string `json:"interval,omitempty"`
	Rules                   []Rule `json:"rules"`
	PartialResponseStrategy string `json:"partial_response_strategy,omitempty"`
}

func (in *RuleGroup) DeepCopyInto(out *RuleGroup) {
	*out = *in
	if in.Rules != nil {
		l := make([]Rule, len(in.Rules))
		for i := range in.Rules {
			in.Rules[i].DeepCopyInto(&l[i])
		}
		out.Rules = l
	}
}

func (in *RuleGroup) DeepCopy() *RuleGroup {
	if in == nil {
		return nil
	}
	out := new(RuleGroup)
	in.DeepCopyInto(out)
	return out
}

type Endpoint struct {
	// Name of the service port this endpoint refers to. Mutually exclusive with targetPort.
	Port string `json:"port,omitempty"`
	// Name or number of the target port of the Pod behind the Service, the port must be specified with container port property. Mutually exclusive with port.
	TargetPort *utilintstr.IntOrString `json:"targetPort,omitempty"`
	// HTTP path to scrape for metrics.
	// If empty, Prometheus uses the default value (e.g. `/metrics`).
	Path string `json:"path,omitempty"`
	// HTTP scheme to use for scraping.
	Scheme string `json:"scheme,omitempty"`
	// Optional HTTP URL parameters
	// This field can not be represented by protobuf.
	// map<string, > params = 5 [(dev.f110.kubeproto.field) = {go_name: "Params", api_field_name: "params", inline: false}];
	// Interval at which metrics should be scraped
	// If not specified Prometheus' global scrape interval is used.
	Interval string `json:"interval"`
	// Timeout after which the scrape is ended
	// If not specified, the Prometheus global scrape timeout is used unless it is less than `Interval` in which the latter is used.
	ScrapeTimeout string `json:"scrapeTimeout"`
	// TLS configuration to use when scraping the endpoint
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// File to read bearer token for scraping targets.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Secret to mount to read bearer token for scraping targets. The secret
	// needs to be in the same namespace as the service monitor and accessible by
	// the Prometheus Operator.
	BearerTokenSecret *corev1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// Authorization section for this endpoint
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// HonorLabels chooses the metric's labels on collisions with target labels.
	HonorLabels bool `json:"honorLabels,omitempty"`
	// HonorTimestamps controls whether Prometheus respects the timestamps present in scraped data.
	HonorTimestamps bool `json:"honorTimestamps,omitempty"`
	// BasicAuth allow an endpoint to authenticate over basic authentication
	// More info: https://prometheus.io/docs/operating/configuration/#endpoints
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Oauth2 for the URL. Only valid in Prometheus versions 2.27.0 and newer.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// MetricRelabelConfigs to apply to samples before ingestion.
	MetricRelabelConfigs []RelabelConfig `json:"metricRelabelings"`
	// RelabelConfigs to apply to samples before scraping.
	// Prometheus Operator automatically adds relabelings for a few standard Kubernetes fields.
	// The original scrape job's name is available via the `__tmp_prometheus_job_name` label.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []RelabelConfig `json:"relabelings"`
	// ProxyURL eg http://proxyserver:2195 Directs scrapes to proxy through this endpoint.
	ProxyURL string `json:"proxyUrl,omitempty"`
	// FollowRedirects configures whether scrape requests follow HTTP 3xx redirects.
	FollowRedirects bool `json:"followRedirects,omitempty"`
	// Whether to enable HTTP2.
	EnableHttp2 bool `json:"enableHttp2,omitempty"`
}

func (in *Endpoint) DeepCopyInto(out *Endpoint) {
	*out = *in
	if in.TargetPort != nil {
		in, out := &in.TargetPort, &out.TargetPort
		*out = new(utilintstr.IntOrString)
		*out = *in
	}
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(TLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.BearerTokenSecret != nil {
		in, out := &in.BearerTokenSecret, &out.BearerTokenSecret
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(SafeAuthorization)
		(*in).DeepCopyInto(*out)
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.OAuth2 != nil {
		in, out := &in.OAuth2, &out.OAuth2
		*out = new(OAuth2)
		(*in).DeepCopyInto(*out)
	}
	if in.MetricRelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.MetricRelabelConfigs))
		for i := range in.MetricRelabelConfigs {
			in.MetricRelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.MetricRelabelConfigs = l
	}
	if in.RelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.RelabelConfigs))
		for i := range in.RelabelConfigs {
			in.RelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.RelabelConfigs = l
	}
}

func (in *Endpoint) DeepCopy() *Endpoint {
	if in == nil {
		return nil
	}
	out := new(Endpoint)
	in.DeepCopyInto(out)
	return out
}

type ObjectReference struct {
	// Group of the referent. When not specified, it defaults to `monitoring.coreos.com`
	Group string `json:"group"`
	// Resource of the referent.
	Resource string `json:"resource"`
	// Namespace of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
	Namespace string `json:"namespace"`
	// Name of the referent. When not set, all resources are matched.
	Name string `json:"name,omitempty"`
}

func (in *ObjectReference) DeepCopyInto(out *ObjectReference) {
	*out = *in
}

func (in *ObjectReference) DeepCopy() *ObjectReference {
	if in == nil {
		return nil
	}
	out := new(ObjectReference)
	in.DeepCopyInto(out)
	return out
}

type TLSConfig struct {
	SafeTLSConfig `json:",inline"`
	// Path to the CA cert in the Prometheus container to use for the targets.
	CAFile string `json:"caFile,omitempty"`
	// Path to the client cert file in the Prometheus container for the targets.
	CertFile string `json:"certFile,omitempty"`
	// Path to the client key file in the Prometheus container for the targets.
	KeyFile string `json:"keyFile,omitempty"`
}

func (in *TLSConfig) DeepCopyInto(out *TLSConfig) {
	*out = *in
	out.SafeTLSConfig = in.SafeTLSConfig
}

func (in *TLSConfig) DeepCopy() *TLSConfig {
	if in == nil {
		return nil
	}
	out := new(TLSConfig)
	in.DeepCopyInto(out)
	return out
}

type EmbeddedPersistentVolumeClaim struct {
	metav1.TypeMeta `json:",inline"`
	// EmbeddedMetadata contains metadata relevant to an EmbeddedResource.
	EmbeddedObjectMetadata *EmbeddedObjectMetadata `json:"metadata,omitempty"`
	// Spec defines the desired characteristics of a volume requested by a pod author.
	// More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
	Spec *corev1.PersistentVolumeClaimSpec `json:"spec,omitempty"`
	// Status represents the current information/status of a persistent volume claim.
	// Read-only.
	// More info: https://kubernetes.io/docs/concepts/storage/persistent-volumes#persistentvolumeclaims
	Status *corev1.PersistentVolumeClaimStatus `json:"status,omitempty"`
}

func (in *EmbeddedPersistentVolumeClaim) DeepCopyInto(out *EmbeddedPersistentVolumeClaim) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.EmbeddedObjectMetadata != nil {
		in, out := &in.EmbeddedObjectMetadata, &out.EmbeddedObjectMetadata
		*out = new(EmbeddedObjectMetadata)
		(*in).DeepCopyInto(*out)
	}
	if in.Spec != nil {
		in, out := &in.Spec, &out.Spec
		*out = new(corev1.PersistentVolumeClaimSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(corev1.PersistentVolumeClaimStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *EmbeddedPersistentVolumeClaim) DeepCopy() *EmbeddedPersistentVolumeClaim {
	if in == nil {
		return nil
	}
	out := new(EmbeddedPersistentVolumeClaim)
	in.DeepCopyInto(out)
	return out
}

func (in *EmbeddedPersistentVolumeClaim) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type WebConfigFileFields struct {
	// Defines the TLS parameters for HTTPS.
	TLSConfig *WebTLSConfig `json:"tlsConfig,omitempty"`
	// Defines HTTP parameters for web server.
	HTTPConfig *WebHTTPConfig `json:"httpConfig,omitempty"`
}

func (in *WebConfigFileFields) DeepCopyInto(out *WebConfigFileFields) {
	*out = *in
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(WebTLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.HTTPConfig != nil {
		in, out := &in.HTTPConfig, &out.HTTPConfig
		*out = new(WebHTTPConfig)
		(*in).DeepCopyInto(*out)
	}
}

func (in *WebConfigFileFields) DeepCopy() *WebConfigFileFields {
	if in == nil {
		return nil
	}
	out := new(WebConfigFileFields)
	in.DeepCopyInto(out)
	return out
}

type AlertmanagerGlobalConfig struct {
	// ResolveTimeout is the default value used by alertmanager if the alert does
	// not include EndsAt, after this time passes it can declare the alert as resolved if it has not been updated.
	// This has no impact on alerts from Prometheus, as they always include EndsAt.
	ResolveTimeout string `json:"resolveTimeout"`
	// HTTP client configuration.
	HTTPConfig *HTTPConfig `json:"httpConfig,omitempty"`
}

func (in *AlertmanagerGlobalConfig) DeepCopyInto(out *AlertmanagerGlobalConfig) {
	*out = *in
	if in.HTTPConfig != nil {
		in, out := &in.HTTPConfig, &out.HTTPConfig
		*out = new(HTTPConfig)
		(*in).DeepCopyInto(*out)
	}
}

func (in *AlertmanagerGlobalConfig) DeepCopy() *AlertmanagerGlobalConfig {
	if in == nil {
		return nil
	}
	out := new(AlertmanagerGlobalConfig)
	in.DeepCopyInto(out)
	return out
}

type PodMetricsEndpointTLSConfig struct {
	SafeTLSConfig `json:",inline"`
}

func (in *PodMetricsEndpointTLSConfig) DeepCopyInto(out *PodMetricsEndpointTLSConfig) {
	*out = *in
	out.SafeTLSConfig = in.SafeTLSConfig
}

func (in *PodMetricsEndpointTLSConfig) DeepCopy() *PodMetricsEndpointTLSConfig {
	if in == nil {
		return nil
	}
	out := new(PodMetricsEndpointTLSConfig)
	in.DeepCopyInto(out)
	return out
}

type ProbeTargetStaticConfig struct {
	// The list of hosts to probe.
	Targets []string `json:"static"`
	// Labels assigned to all metrics scraped from the targets.
	Labels map[string]string `json:"labels,omitempty"`
	// RelabelConfigs to apply to the label set of the targets before it gets
	// scraped.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []RelabelConfig `json:"relabelingConfigs"`
}

func (in *ProbeTargetStaticConfig) DeepCopyInto(out *ProbeTargetStaticConfig) {
	*out = *in
	if in.Targets != nil {
		t := make([]string, len(in.Targets))
		copy(t, in.Targets)
		out.Targets = t
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.RelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.RelabelConfigs))
		for i := range in.RelabelConfigs {
			in.RelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.RelabelConfigs = l
	}
}

func (in *ProbeTargetStaticConfig) DeepCopy() *ProbeTargetStaticConfig {
	if in == nil {
		return nil
	}
	out := new(ProbeTargetStaticConfig)
	in.DeepCopyInto(out)
	return out
}

type ProbeTargetIngress struct {
	// Selector to select the Ingress objects.
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
	// From which namespaces to select Ingress objects.
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`
	// RelabelConfigs to apply to the label set of the target before it gets
	// scraped.
	// The original ingress address is available via the
	// `__tmp_prometheus_ingress_address` label. It can be used to customize the
	// probed URL.
	// The original scrape job's name is available via the `__tmp_prometheus_job_name` label.
	// More info: https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
	RelabelConfigs []RelabelConfig `json:"relabelingConfigs"`
}

func (in *ProbeTargetIngress) DeepCopyInto(out *ProbeTargetIngress) {
	*out = *in
	if in.Selector != nil {
		in, out := &in.Selector, &out.Selector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(NamespaceSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.RelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.RelabelConfigs))
		for i := range in.RelabelConfigs {
			in.RelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.RelabelConfigs = l
	}
}

func (in *ProbeTargetIngress) DeepCopy() *ProbeTargetIngress {
	if in == nil {
		return nil
	}
	out := new(ProbeTargetIngress)
	in.DeepCopyInto(out)
	return out
}

type SafeTLSConfig struct {
	// Struct containing the CA cert to use for the targets.
	CA *SecretOrConfigMap `json:"ca,omitempty"`
	// Struct containing the client cert file for the targets.
	Cert *SecretOrConfigMap `json:"cert,omitempty"`
	// Secret containing the client key file for the targets.
	KeySecret *corev1.SecretKeySelector `json:"keySecret,omitempty"`
	// Used to verify the hostname for the targets.
	ServerName string `json:"serverName,omitempty"`
	// Disable target certificate validation.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

func (in *SafeTLSConfig) DeepCopyInto(out *SafeTLSConfig) {
	*out = *in
	if in.CA != nil {
		in, out := &in.CA, &out.CA
		*out = new(SecretOrConfigMap)
		(*in).DeepCopyInto(*out)
	}
	if in.Cert != nil {
		in, out := &in.Cert, &out.Cert
		*out = new(SecretOrConfigMap)
		(*in).DeepCopyInto(*out)
	}
	if in.KeySecret != nil {
		in, out := &in.KeySecret, &out.KeySecret
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *SafeTLSConfig) DeepCopy() *SafeTLSConfig {
	if in == nil {
		return nil
	}
	out := new(SafeTLSConfig)
	in.DeepCopyInto(out)
	return out
}

type SecretOrConfigMap struct {
	// Secret containing data to use for the targets.
	Secret *corev1.SecretKeySelector `json:"secret,omitempty"`
	// ConfigMap containing data to use for the targets.
	ConfigMap *corev1.ConfigMapKeySelector `json:"configMap,omitempty"`
}

func (in *SecretOrConfigMap) DeepCopyInto(out *SecretOrConfigMap) {
	*out = *in
	if in.Secret != nil {
		in, out := &in.Secret, &out.Secret
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ConfigMap != nil {
		in, out := &in.ConfigMap, &out.ConfigMap
		*out = new(corev1.ConfigMapKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *SecretOrConfigMap) DeepCopy() *SecretOrConfigMap {
	if in == nil {
		return nil
	}
	out := new(SecretOrConfigMap)
	in.DeepCopyInto(out)
	return out
}

type PrometheusWebSpec struct {
	WebConfigFileFields `json:",inline"`
	// The prometheus web page title
	PageTitle string `json:"pageTitle,omitempty"`
}

func (in *PrometheusWebSpec) DeepCopyInto(out *PrometheusWebSpec) {
	*out = *in
	out.WebConfigFileFields = in.WebConfigFileFields
}

func (in *PrometheusWebSpec) DeepCopy() *PrometheusWebSpec {
	if in == nil {
		return nil
	}
	out := new(PrometheusWebSpec)
	in.DeepCopyInto(out)
	return out
}

type RemoteWriteSpec struct {
	// The URL of the endpoint to send samples to.
	URL string `json:"url"`
	// The name of the remote write queue, it must be unique if specified. The
	// name is used in metrics and logging in order to differentiate queues.
	// Only valid in Prometheus versions 2.15.0 and newer.
	Name string `json:"name,omitempty"`
	// Enables sending of exemplars over remote write. Note that
	// exemplar-storage itself must be enabled using the enableFeature option
	// for exemplars to be scraped in the first place.  Only valid in
	// Prometheus versions 2.27.0 and newer.
	SendExemplars bool `json:"sendExemplars,omitempty"`
	// Timeout for requests to the remote write endpoint.
	RemoteTimeout string `json:"remoteTimeout"`
	// Custom HTTP headers to be sent along with each remote write request.
	// Be aware that headers that are set by Prometheus itself can't be overwritten.
	// Only valid in Prometheus versions 2.25.0 and newer.
	Headers map[string]string `json:"headers,omitempty"`
	// The list of remote write relabel configurations.
	WriteRelabelConfigs []RelabelConfig `json:"writeRelabelConfigs"`
	// Oauth2 for the URL. Only valid in Prometheus versions 2.27.0 and newer.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// BasicAuth for the URL.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Bearer token for remote write.
	BearerToken string `json:"bearerToken,omitempty"`
	// File to read bearer token for remote write.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Authorization section for remote write
	Authorization *Authorization `json:"authorization,omitempty"`
	// Sigv4 allows to configures AWS's Signature Verification 4
	Sigv4 *Sigv4 `json:"sigv4,omitempty"`
	// TLS Config to use for remote write.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Optional ProxyURL.
	ProxyURL string `json:"proxyUrl,omitempty"`
	// QueueConfig allows tuning of the remote write queue parameters.
	QueueConfig *QueueConfig `json:"queueConfig,omitempty"`
	// MetadataConfig configures the sending of series metadata to the remote storage.
	MetadataConfig *MetadataConfig `json:"metadataConfig,omitempty"`
}

func (in *RemoteWriteSpec) DeepCopyInto(out *RemoteWriteSpec) {
	*out = *in
	if in.Headers != nil {
		in, out := &in.Headers, &out.Headers
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.WriteRelabelConfigs != nil {
		l := make([]RelabelConfig, len(in.WriteRelabelConfigs))
		for i := range in.WriteRelabelConfigs {
			in.WriteRelabelConfigs[i].DeepCopyInto(&l[i])
		}
		out.WriteRelabelConfigs = l
	}
	if in.OAuth2 != nil {
		in, out := &in.OAuth2, &out.OAuth2
		*out = new(OAuth2)
		(*in).DeepCopyInto(*out)
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(Authorization)
		(*in).DeepCopyInto(*out)
	}
	if in.Sigv4 != nil {
		in, out := &in.Sigv4, &out.Sigv4
		*out = new(Sigv4)
		(*in).DeepCopyInto(*out)
	}
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(TLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.QueueConfig != nil {
		in, out := &in.QueueConfig, &out.QueueConfig
		*out = new(QueueConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.MetadataConfig != nil {
		in, out := &in.MetadataConfig, &out.MetadataConfig
		*out = new(MetadataConfig)
		(*in).DeepCopyInto(*out)
	}
}

func (in *RemoteWriteSpec) DeepCopy() *RemoteWriteSpec {
	if in == nil {
		return nil
	}
	out := new(RemoteWriteSpec)
	in.DeepCopyInto(out)
	return out
}

type APIServerConfig struct {
	// Host of apiserver.
	// A valid string consisting of a hostname or IP followed by an optional port number
	Host string `json:"host"`
	// BasicAuth allow an endpoint to authenticate over basic authentication
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Bearer token for accessing apiserver.
	BearerToken string `json:"bearerToken,omitempty"`
	// File to read bearer token for accessing apiserver.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// TLS Config to use for accessing apiserver.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// Authorization section for accessing apiserver
	Authorization *Authorization `json:"authorization,omitempty"`
}

func (in *APIServerConfig) DeepCopyInto(out *APIServerConfig) {
	*out = *in
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(TLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(Authorization)
		(*in).DeepCopyInto(*out)
	}
}

func (in *APIServerConfig) DeepCopy() *APIServerConfig {
	if in == nil {
		return nil
	}
	out := new(APIServerConfig)
	in.DeepCopyInto(out)
	return out
}

type ArbitraryFSAccessThroughSMsConfig struct {
	Deny bool `json:"deny,omitempty"`
}

func (in *ArbitraryFSAccessThroughSMsConfig) DeepCopyInto(out *ArbitraryFSAccessThroughSMsConfig) {
	*out = *in
}

func (in *ArbitraryFSAccessThroughSMsConfig) DeepCopy() *ArbitraryFSAccessThroughSMsConfig {
	if in == nil {
		return nil
	}
	out := new(ArbitraryFSAccessThroughSMsConfig)
	in.DeepCopyInto(out)
	return out
}

type Argument struct {
	// Name of the argument, e.g. "scrape.discovery-reload-interval".
	Name string `json:"name"`
	// Argument value, e.g. 30s. Can be empty for name-only arguments (e.g. --storage.tsdb.no-lockfile)
	Value string `json:"value,omitempty"`
}

func (in *Argument) DeepCopyInto(out *Argument) {
	*out = *in
}

func (in *Argument) DeepCopy() *Argument {
	if in == nil {
		return nil
	}
	out := new(Argument)
	in.DeepCopyInto(out)
	return out
}

type RulesAlert struct {
	// Max time to tolerate prometheus outage for restoring 'for' state of alert.
	ForOutageTolerance string `json:"forOutageTolerance,omitempty"`
	// Minimum duration between alert and restored 'for' state.
	// This is maintained only for alerts with configured 'for' time greater than grace period.
	ForGracePeriod string `json:"forGracePeriod,omitempty"`
	// Minimum amount of time to wait before resending an alert to Alertmanager.
	ResendDelay string `json:"resendDelay,omitempty"`
}

func (in *RulesAlert) DeepCopyInto(out *RulesAlert) {
	*out = *in
}

func (in *RulesAlert) DeepCopy() *RulesAlert {
	if in == nil {
		return nil
	}
	out := new(RulesAlert)
	in.DeepCopyInto(out)
	return out
}

type AlertmanagerEndpoints struct {
	// Namespace of Endpoints object.
	Namespace string `json:"namespace"`
	// Name of Endpoints object in Namespace.
	Name string `json:"name"`
	// Port the Alertmanager API is exposed on.
	Port utilintstr.IntOrString `json:"port"`
	// Scheme to use when firing alerts.
	Scheme string `json:"scheme,omitempty"`
	// Prefix for the HTTP path alerts are pushed to.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// TLS Config to use for alertmanager connection.
	TLSConfig *TLSConfig `json:"tlsConfig,omitempty"`
	// BearerTokenFile to read from filesystem to use when authenticating to
	// Alertmanager.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Authorization section for this alertmanager endpoint
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// Version of the Alertmanager API that Prometheus uses to send alerts. It
	// can be "v1" or "v2".
	APIVersion string `json:"apiVersion,omitempty"`
	// Timeout is a per-target Alertmanager timeout when pushing alerts.
	Timeout string `json:"timeout"`
}

func (in *AlertmanagerEndpoints) DeepCopyInto(out *AlertmanagerEndpoints) {
	*out = *in
	in = out
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(TLSConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(SafeAuthorization)
		(*in).DeepCopyInto(*out)
	}
}

func (in *AlertmanagerEndpoints) DeepCopy() *AlertmanagerEndpoints {
	if in == nil {
		return nil
	}
	out := new(AlertmanagerEndpoints)
	in.DeepCopyInto(out)
	return out
}

type Authorization struct {
	SafeAuthorization `json:",inline"`
	// File to read a secret from, mutually exclusive with Credentials (from SafeAuthorization)
	CredentialsFile string `json:"credentialsFile,omitempty"`
}

func (in *Authorization) DeepCopyInto(out *Authorization) {
	*out = *in
	out.SafeAuthorization = in.SafeAuthorization
}

func (in *Authorization) DeepCopy() *Authorization {
	if in == nil {
		return nil
	}
	out := new(Authorization)
	in.DeepCopyInto(out)
	return out
}

type Rule struct {
	Record      string                 `json:"record,omitempty"`
	Alert       string                 `json:"alert,omitempty"`
	Expr        utilintstr.IntOrString `json:"expr"`
	For         string                 `json:"for,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
}

func (in *Rule) DeepCopyInto(out *Rule) {
	*out = *in
	in = out
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
}

func (in *Rule) DeepCopy() *Rule {
	if in == nil {
		return nil
	}
	out := new(Rule)
	in.DeepCopyInto(out)
	return out
}

type WebTLSConfig struct {
	// Secret containing the TLS key for the server.
	KeySecret corev1.SecretKeySelector `json:"keySecret"`
	// Contains the TLS certificate for the server.
	Cert SecretOrConfigMap `json:"cert"`
	// Server policy for client authentication. Maps to ClientAuth Policies.
	// For more detail on clientAuth options:
	// https://golang.org/pkg/crypto/tls/#ClientAuthType
	ClientAuthType string `json:"clientAuthType,omitempty"`
	// Contains the CA certificate for client certificate authentication to the server.
	ClientCA *SecretOrConfigMap `json:"client_ca,omitempty"`
	// Minimum TLS version that is acceptable. Defaults to TLS12.
	MinVersion string `json:"minVersion,omitempty"`
	// Maximum TLS version that is acceptable. Defaults to TLS13.
	MaxVersion string `json:"maxVersion,omitempty"`
	// List of supported cipher suites for TLS versions up to TLS 1.2. If empty,
	// Go default cipher suites are used. Available cipher suites are documented
	// in the go documentation: https://golang.org/pkg/crypto/tls/#pkg-constants
	CipherSuites []string `json:"cipherSuites"`
	// Controls whether the server selects the
	// client's most preferred cipher suite, or the server's most preferred
	// cipher suite. If true then the server's preference, as expressed in
	// the order of elements in cipherSuites, is used.
	PreferServerCipherSuites bool `json:"preferServerCipherSuites,omitempty"`
	// Elliptic curves that will be used in an ECDHE handshake, in preference
	// order. Available curves are documented in the go documentation:
	// https://golang.org/pkg/crypto/tls/#CurveID
	CurvePreferences []string `json:"curvePreferences"`
}

func (in *WebTLSConfig) DeepCopyInto(out *WebTLSConfig) {
	*out = *in
	in.KeySecret.DeepCopyInto(&out.KeySecret)
	in.Cert.DeepCopyInto(&out.Cert)
	if in.ClientCA != nil {
		in, out := &in.ClientCA, &out.ClientCA
		*out = new(SecretOrConfigMap)
		(*in).DeepCopyInto(*out)
	}
	if in.CipherSuites != nil {
		t := make([]string, len(in.CipherSuites))
		copy(t, in.CipherSuites)
		out.CipherSuites = t
	}
	if in.CurvePreferences != nil {
		t := make([]string, len(in.CurvePreferences))
		copy(t, in.CurvePreferences)
		out.CurvePreferences = t
	}
}

func (in *WebTLSConfig) DeepCopy() *WebTLSConfig {
	if in == nil {
		return nil
	}
	out := new(WebTLSConfig)
	in.DeepCopyInto(out)
	return out
}

type WebHTTPConfig struct {
	// Enable HTTP/2 support. Note that HTTP/2 is only supported with TLS.
	// When TLSConfig is not configured, HTTP/2 will be disabled.
	// Whenever the value of the field changes, a rolling update will be triggered.
	HTTP2 bool `json:"http2,omitempty"`
	// List of headers that can be added to HTTP responses.
	Headers *WebHTTPHeaders `json:"headers,omitempty"`
}

func (in *WebHTTPConfig) DeepCopyInto(out *WebHTTPConfig) {
	*out = *in
	if in.Headers != nil {
		in, out := &in.Headers, &out.Headers
		*out = new(WebHTTPHeaders)
		(*in).DeepCopyInto(*out)
	}
}

func (in *WebHTTPConfig) DeepCopy() *WebHTTPConfig {
	if in == nil {
		return nil
	}
	out := new(WebHTTPConfig)
	in.DeepCopyInto(out)
	return out
}

type HTTPConfig struct {
	// Authorization header configuration for the client.
	// This is mutually exclusive with BasicAuth and is only available starting from Alertmanager v0.22+.
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// BasicAuth for the client.
	// This is mutually exclusive with Authorization. If both are defined, BasicAuth takes precedence.
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// Oauth2 client credentials used to fetch a token for the targets.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// The secret's key that contains the bearer token to be used by the client
	// for authentication.
	// The secret needs to be in the same namespace as the Alertmanager
	// object and accessible by the Prometheus Operator.
	BearerTokenSecret *corev1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// TLS configuration for the client.
	TLSConfig *SafeTLSConfig `json:"tlsConfig,omitempty"`
	// Optional proxy URL.
	ProxyURL string `json:"proxyURL,omitempty"`
	// FollowRedirects specifies whether the client should follow HTTP 3xx redirects.
	FollowRedirects bool `json:"followRedirects,omitempty"`
}

func (in *HTTPConfig) DeepCopyInto(out *HTTPConfig) {
	*out = *in
	if in.Authorization != nil {
		in, out := &in.Authorization, &out.Authorization
		*out = new(SafeAuthorization)
		(*in).DeepCopyInto(*out)
	}
	if in.BasicAuth != nil {
		in, out := &in.BasicAuth, &out.BasicAuth
		*out = new(BasicAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.OAuth2 != nil {
		in, out := &in.OAuth2, &out.OAuth2
		*out = new(OAuth2)
		(*in).DeepCopyInto(*out)
	}
	if in.BearerTokenSecret != nil {
		in, out := &in.BearerTokenSecret, &out.BearerTokenSecret
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.TLSConfig != nil {
		in, out := &in.TLSConfig, &out.TLSConfig
		*out = new(SafeTLSConfig)
		(*in).DeepCopyInto(*out)
	}
}

func (in *HTTPConfig) DeepCopy() *HTTPConfig {
	if in == nil {
		return nil
	}
	out := new(HTTPConfig)
	in.DeepCopyInto(out)
	return out
}

type Sigv4 struct {
	// Region is the AWS region. If blank, the region from the default credentials chain used.
	Region string `json:"region,omitempty"`
	// AccessKey is the AWS API key. If blank, the environment variable `AWS_ACCESS_KEY_ID` is used.
	AccessKey *corev1.SecretKeySelector `json:"accessKey,omitempty"`
	// SecretKey is the AWS API secret. If blank, the environment variable `AWS_SECRET_ACCESS_KEY` is used.
	SecretKey *corev1.SecretKeySelector `json:"secretKey,omitempty"`
	// Profile is the named AWS profile used to authenticate.
	Profile string `json:"profile,omitempty"`
	// RoleArn is the named AWS profile used to authenticate.
	RoleArn string `json:"roleArn,omitempty"`
}

func (in *Sigv4) DeepCopyInto(out *Sigv4) {
	*out = *in
	if in.AccessKey != nil {
		in, out := &in.AccessKey, &out.AccessKey
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.SecretKey != nil {
		in, out := &in.SecretKey, &out.SecretKey
		*out = new(corev1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *Sigv4) DeepCopy() *Sigv4 {
	if in == nil {
		return nil
	}
	out := new(Sigv4)
	in.DeepCopyInto(out)
	return out
}

type QueueConfig struct {
	// Capacity is the number of samples to buffer per shard before we start dropping them.
	Capacity int `json:"capacity,omitempty"`
	// MinShards is the minimum number of shards, i.e. amount of concurrency.
	MinShards int `json:"minShards,omitempty"`
	// MaxShards is the maximum number of shards, i.e. amount of concurrency.
	MaxShards int `json:"maxShards,omitempty"`
	// MaxSamplesPerSend is the maximum number of samples per send.
	MaxSamplesPerSend int `json:"maxSamplesPerSend,omitempty"`
	// BatchSendDeadline is the maximum time a sample will wait in buffer.
	BatchSendDeadline string `json:"batchSendDeadline,omitempty"`
	// MaxRetries is the maximum number of times to retry a batch on recoverable errors.
	MaxRetries int `json:"maxRetries,omitempty"`
	// MinBackoff is the initial retry delay. Gets doubled for every retry.
	MinBackoff string `json:"minBackoff,omitempty"`
	// MaxBackoff is the maximum retry delay.
	MaxBackoff string `json:"maxBackoff,omitempty"`
	// Retry upon receiving a 429 status code from the remote-write storage.
	// This is experimental feature and might change in the future.
	RetryOnRateLimit bool `json:"retryOnRateLimit,omitempty"`
}

func (in *QueueConfig) DeepCopyInto(out *QueueConfig) {
	*out = *in
}

func (in *QueueConfig) DeepCopy() *QueueConfig {
	if in == nil {
		return nil
	}
	out := new(QueueConfig)
	in.DeepCopyInto(out)
	return out
}

type MetadataConfig struct {
	// Whether metric metadata is sent to the remote storage or not.
	Send bool `json:"send,omitempty"`
	// How frequently metric metadata is sent to the remote storage.
	SendInterval string `json:"sendInterval"`
}

func (in *MetadataConfig) DeepCopyInto(out *MetadataConfig) {
	*out = *in
}

func (in *MetadataConfig) DeepCopy() *MetadataConfig {
	if in == nil {
		return nil
	}
	out := new(MetadataConfig)
	in.DeepCopyInto(out)
	return out
}

type WebHTTPHeaders struct {
	// Set the Content-Security-Policy header to HTTP responses.
	// Unset if blank.
	ContentSecurityPolicy string `json:"contentSecurityPolicy,omitempty"`
	// Set the X-Frame-Options header to HTTP responses.
	// Unset if blank. Accepted values are deny and sameorigin.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
	XFrameOptions string `json:"xFrameOptions,omitempty"`
	// Set the X-Content-Type-Options header to HTTP responses.
	// Unset if blank. Accepted value is nosniff.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
	XContentTypeOptions string `json:"xContentTypeOptions,omitempty"`
	// Set the X-XSS-Protection header to all responses.
	// Unset if blank.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
	XXSSProtection string `json:"xXSSProtection,omitempty"`
	// Set the Strict-Transport-Security header to HTTP responses.
	// Unset if blank.
	// Please make sure that you use this with care as this header might force
	// browsers to load Prometheus and the other applications hosted on the same
	// domain and subdomains over HTTPS.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
	StrictTransportSecurity string `json:"strictTransportSecurity,omitempty"`
}

func (in *WebHTTPHeaders) DeepCopyInto(out *WebHTTPHeaders) {
	*out = *in
}

func (in *WebHTTPHeaders) DeepCopy() *WebHTTPHeaders {
	if in == nil {
		return nil
	}
	out := new(WebHTTPHeaders)
	in.DeepCopyInto(out)
	return out
}
