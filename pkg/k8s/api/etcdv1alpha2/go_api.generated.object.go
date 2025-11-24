package etcdv1alpha2

import (
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const GroupName = "etcd.f110.dev"

var (
	GroupVersion       = metav1.GroupVersion{Group: GroupName, Version: "v1alpha2"}
	SchemeBuilder      = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme        = SchemeBuilder.AddToScheme
	SchemaGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1alpha2"}
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemaGroupVersion,
		&EtcdCluster{},
		&EtcdClusterList{},
	)
	metav1.AddToGroupVersion(scheme, SchemaGroupVersion)
	return nil
}

type EtcdClusterPhase string

const (
	EtcdClusterPhasePending      EtcdClusterPhase = "Pending"
	EtcdClusterPhaseInitializing EtcdClusterPhase = "Initializing"
	EtcdClusterPhaseCreating     EtcdClusterPhase = "Creating"
	EtcdClusterPhaseRunning      EtcdClusterPhase = "Running"
	EtcdClusterPhaseUpdating     EtcdClusterPhase = "Updating"
	EtcdClusterPhaseDegrading    EtcdClusterPhase = "Degrading"
)

type EtcdCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              EtcdClusterSpec   `json:"spec"`
	Status            EtcdClusterStatus `json:"status"`
}

func (in *EtcdCluster) DeepCopyInto(out *EtcdCluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *EtcdCluster) DeepCopy() *EtcdCluster {
	if in == nil {
		return nil
	}
	out := new(EtcdCluster)
	in.DeepCopyInto(out)
	return out
}

func (in *EtcdCluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type EtcdClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []EtcdCluster `json:"items"`
}

func (in *EtcdClusterList) DeepCopyInto(out *EtcdClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]EtcdCluster, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *EtcdClusterList) DeepCopy() *EtcdClusterList {
	if in == nil {
		return nil
	}
	out := new(EtcdClusterList)
	in.DeepCopyInto(out)
	return out
}

func (in *EtcdClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type EtcdClusterSpec struct {
	Members             int                                   `json:"members"`
	Version             string                                `json:"version"`
	AntiAffinity        bool                                  `json:"antiAffinity,omitempty"`
	DefragmentSchedule  string                                `json:"defragmentSchedule"`
	Template            *PodTemplateSpec                      `json:"template,omitempty"`
	Backup              *BackupSpec                           `json:"backup,omitempty"`
	VolumeClaimTemplate *corev1.PersistentVolumeClaimTemplate `json:"volumeClaimTemplate,omitempty"`
	Development         bool                                  `json:"development,omitempty"`
}

func (in *EtcdClusterSpec) DeepCopyInto(out *EtcdClusterSpec) {
	*out = *in
	if in.Template != nil {
		in, out := &in.Template, &out.Template
		*out = new(PodTemplateSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.Backup != nil {
		in, out := &in.Backup, &out.Backup
		*out = new(BackupSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.VolumeClaimTemplate != nil {
		in, out := &in.VolumeClaimTemplate, &out.VolumeClaimTemplate
		*out = new(corev1.PersistentVolumeClaimTemplate)
		(*in).DeepCopyInto(*out)
	}
}

func (in *EtcdClusterSpec) DeepCopy() *EtcdClusterSpec {
	if in == nil {
		return nil
	}
	out := new(EtcdClusterSpec)
	in.DeepCopyInto(out)
	return out
}

type EtcdClusterStatus struct {
	Ready                   bool             `json:"ready"`
	Phase                   EtcdClusterPhase `json:"phase,omitempty"`
	Members                 []MemberStatus   `json:"members"`
	LastReadyTransitionTime *metav1.Time     `json:"lastReadyTransitionTime,omitempty"`
	LastDefragmentTime      *metav1.Time     `json:"lastDefragmentTime,omitempty"`
	CreatingCompleted       bool             `json:"creatingCompleted,omitempty"`
	ClientEndpoint          string           `json:"clientEndpoint,omitempty"`
	ClientCertSecretName    string           `json:"clientCertSecretName,omitempty"`
	Backup                  *BackupStatus    `json:"backup,omitempty"`
	Restored                *RestoredStatus  `json:"restored,omitempty"`
}

func (in *EtcdClusterStatus) DeepCopyInto(out *EtcdClusterStatus) {
	*out = *in
	if in.Members != nil {
		l := make([]MemberStatus, len(in.Members))
		for i := range in.Members {
			in.Members[i].DeepCopyInto(&l[i])
		}
		out.Members = l
	}
	if in.LastReadyTransitionTime != nil {
		in, out := &in.LastReadyTransitionTime, &out.LastReadyTransitionTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
	if in.LastDefragmentTime != nil {
		in, out := &in.LastDefragmentTime, &out.LastDefragmentTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
	if in.Backup != nil {
		in, out := &in.Backup, &out.Backup
		*out = new(BackupStatus)
		(*in).DeepCopyInto(*out)
	}
	if in.Restored != nil {
		in, out := &in.Restored, &out.Restored
		*out = new(RestoredStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *EtcdClusterStatus) DeepCopy() *EtcdClusterStatus {
	if in == nil {
		return nil
	}
	out := new(EtcdClusterStatus)
	in.DeepCopyInto(out)
	return out
}

type PodTemplateSpec struct {
	Metadata *ObjectMeta `json:"metadata,omitempty"`
}

func (in *PodTemplateSpec) DeepCopyInto(out *PodTemplateSpec) {
	*out = *in
	if in.Metadata != nil {
		in, out := &in.Metadata, &out.Metadata
		*out = new(ObjectMeta)
		(*in).DeepCopyInto(*out)
	}
}

func (in *PodTemplateSpec) DeepCopy() *PodTemplateSpec {
	if in == nil {
		return nil
	}
	out := new(PodTemplateSpec)
	in.DeepCopyInto(out)
	return out
}

type BackupSpec struct {
	IntervalInSeconds int                `json:"intervalInSeconds,omitempty"`
	MaxBackups        int                `json:"maxBackups,omitempty"`
	Storage           *BackupStorageSpec `json:"storage,omitempty"`
}

func (in *BackupSpec) DeepCopyInto(out *BackupSpec) {
	*out = *in
	if in.Storage != nil {
		in, out := &in.Storage, &out.Storage
		*out = new(BackupStorageSpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BackupSpec) DeepCopy() *BackupSpec {
	if in == nil {
		return nil
	}
	out := new(BackupSpec)
	in.DeepCopyInto(out)
	return out
}

type MemberStatus struct {
	Id        int64  `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	PodName   string `json:"podName,omitempty"`
	Leader    bool   `json:"leader,omitempty"`
	Learner   bool   `json:"learner,omitempty"`
	Version   string `json:"version,omitempty"`
	DBSize    int64  `json:"dbSize,omitempty"`
	InUseSize int64  `json:"inUseSize,omitempty"`
}

func (in *MemberStatus) DeepCopyInto(out *MemberStatus) {
	*out = *in
}

func (in *MemberStatus) DeepCopy() *MemberStatus {
	if in == nil {
		return nil
	}
	out := new(MemberStatus)
	in.DeepCopyInto(out)
	return out
}

type BackupStatus struct {
	Succeeded         bool                  `json:"succeeded,omitempty"`
	LastSucceededTime *metav1.Time          `json:"lastSucceededTime,omitempty"`
	History           []BackupStatusHistory `json:"backupStatusHistory"`
}

func (in *BackupStatus) DeepCopyInto(out *BackupStatus) {
	*out = *in
	if in.LastSucceededTime != nil {
		in, out := &in.LastSucceededTime, &out.LastSucceededTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
	if in.History != nil {
		l := make([]BackupStatusHistory, len(in.History))
		for i := range in.History {
			in.History[i].DeepCopyInto(&l[i])
		}
		out.History = l
	}
}

func (in *BackupStatus) DeepCopy() *BackupStatus {
	if in == nil {
		return nil
	}
	out := new(BackupStatus)
	in.DeepCopyInto(out)
	return out
}

type RestoredStatus struct {
	Completed    bool         `json:"completed,omitempty"`
	Path         string       `json:"path,omitempty"`
	BackupTime   *metav1.Time `json:"backupTime,omitempty"`
	RestoredTime *metav1.Time `json:"restoredTime,omitempty"`
}

func (in *RestoredStatus) DeepCopyInto(out *RestoredStatus) {
	*out = *in
	if in.BackupTime != nil {
		in, out := &in.BackupTime, &out.BackupTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
	if in.RestoredTime != nil {
		in, out := &in.RestoredTime, &out.RestoredTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *RestoredStatus) DeepCopy() *RestoredStatus {
	if in == nil {
		return nil
	}
	out := new(RestoredStatus)
	in.DeepCopyInto(out)
	return out
}

type ObjectMeta struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (in *ObjectMeta) DeepCopyInto(out *ObjectMeta) {
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

func (in *ObjectMeta) DeepCopy() *ObjectMeta {
	if in == nil {
		return nil
	}
	out := new(ObjectMeta)
	in.DeepCopyInto(out)
	return out
}

type BackupStorageSpec struct {
	MinIO *BackupStorageMinIOSpec `json:"minio,omitempty"`
	GCS   *BackupStorageGCSSpec   `json:"gcs,omitempty"`
}

func (in *BackupStorageSpec) DeepCopyInto(out *BackupStorageSpec) {
	*out = *in
	if in.MinIO != nil {
		in, out := &in.MinIO, &out.MinIO
		*out = new(BackupStorageMinIOSpec)
		(*in).DeepCopyInto(*out)
	}
	if in.GCS != nil {
		in, out := &in.GCS, &out.GCS
		*out = new(BackupStorageGCSSpec)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BackupStorageSpec) DeepCopy() *BackupStorageSpec {
	if in == nil {
		return nil
	}
	out := new(BackupStorageSpec)
	in.DeepCopyInto(out)
	return out
}

type BackupStatusHistory struct {
	Succeeded    bool         `json:"succeeded,omitempty"`
	ExecuteTime  *metav1.Time `json:"executeTime,omitempty"`
	Path         string       `json:"path,omitempty"`
	EtcdVersion  string       `json:"etcdVersion,omitempty"`
	EtcdRevision int64        `json:"etcdRevision,omitempty"`
	Message      string       `json:"message,omitempty"`
}

func (in *BackupStatusHistory) DeepCopyInto(out *BackupStatusHistory) {
	*out = *in
	if in.ExecuteTime != nil {
		in, out := &in.ExecuteTime, &out.ExecuteTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BackupStatusHistory) DeepCopy() *BackupStatusHistory {
	if in == nil {
		return nil
	}
	out := new(BackupStatusHistory)
	in.DeepCopyInto(out)
	return out
}

type BackupStorageMinIOSpec struct {
	ServiceSelector    *ObjectSelector        `json:"serviceSelector,omitempty"`
	CredentialSelector *AWSCredentialSelector `json:"credentialSelector,omitempty"`
	Bucket             string                 `json:"bucket,omitempty"`
	Path               string                 `json:"path,omitempty"`
	Secure             bool                   `json:"secure,omitempty"`
}

func (in *BackupStorageMinIOSpec) DeepCopyInto(out *BackupStorageMinIOSpec) {
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

func (in *BackupStorageMinIOSpec) DeepCopy() *BackupStorageMinIOSpec {
	if in == nil {
		return nil
	}
	out := new(BackupStorageMinIOSpec)
	in.DeepCopyInto(out)
	return out
}

type BackupStorageGCSSpec struct {
	Bucket             string                 `json:"bucket,omitempty"`
	Path               string                 `json:"path,omitempty"`
	CredentialSelector *GCPCredentialSelector `json:"credentialSelector,omitempty"`
}

func (in *BackupStorageGCSSpec) DeepCopyInto(out *BackupStorageGCSSpec) {
	*out = *in
	if in.CredentialSelector != nil {
		in, out := &in.CredentialSelector, &out.CredentialSelector
		*out = new(GCPCredentialSelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *BackupStorageGCSSpec) DeepCopy() *BackupStorageGCSSpec {
	if in == nil {
		return nil
	}
	out := new(BackupStorageGCSSpec)
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
	AccessKeyIDKey     string `json:"accessKeyIDKey,omitempty"`
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
	ServiceAccountJSONKey string `json:"serviceAccountJSONKey,omitempty"`
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
