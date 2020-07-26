package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type EtcdClusterPhase string

const (
	ClusterPhasePending      EtcdClusterPhase = "Pending"
	ClusterPhaseInitializing EtcdClusterPhase = "Initializing"
	ClusterPhaseCreating     EtcdClusterPhase = "Creating"
	ClusterPhaseRunning      EtcdClusterPhase = "Running"
	ClusterPhaseUpdating     EtcdClusterPhase = "Updating"
	ClusterPhaseDegrading    EtcdClusterPhase = "Degrading"
)

type StorageType string

const (
	StorageMemory     StorageType = "memory"
	StoragePersistent StorageType = "persistent"
)

type ObjectSelector struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type AWSCredentialSelector struct {
	Name               string `json:"name,omitempty"`
	Namespace          string `json:"namespace,omitempty"`
	AccessKeyIDKey     string `json:"accessKeyIDKey,omitempty"`
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`
}

type GCPCredentialSelector struct {
	Name                  string `json:"name,omitempty"`
	Namespace             string `json:"namespace,omitempty"`
	ServiceAccountJSONKey string `json:"serviceAccountJSONKey,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="ready",type="string",JSONPath=".status.ready",description="Ready",format="byte",priority=0
// +kubebuilder:printcolumn:name="phase",type="string",JSONPath=".status.phase",description="Phase",format="byte",priority=0
// +kubebuilder:printcolumn:name="members",type="string",JSONPath=".spec.members",description="Members",format="byte",priority=0
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp",description="Age",format="date",priority=0

type EtcdCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EtcdClusterSpec   `json:"spec,omitempty"`
	Status EtcdClusterStatus `json:"status,omitempty"`
}

type EtcdClusterSpec struct {
	Members            int         `json:"members"`
	Version            string      `json:"version"`
	DefragmentSchedule string      `json:"defragmentSchedule"`
	Backup             *BackupSpec `json:"backup,omitempty"`
}

type BackupSpec struct {
	IntervalInSecond int               `json:"intervalInSeconds,omitempty"`
	MaxBackups       int               `json:"maxBackups,omitempty"`
	Storage          BackupStorageSpec `json:"storage,omitempty"`
}

type BackupStorageSpec struct {
	// MinIO is in-cluster MinIO config
	MinIO *BackupStorageMinIOSpec `json:"minio,omitempty"`
	GCS   *BackupStorageGCSSpec   `json:"gcs,omitempty"`
}

type BackupStorageMinIOSpec struct {
	ServiceSelector    ObjectSelector        `json:"serviceSelector,omitempty"`
	CredentialSelector AWSCredentialSelector `json:"credentialSelector,omitempty"`
	Bucket             string                `json:"bucket,omitempty"`
	Path               string                `json:"path,omitempty"`
	Secure             bool                  `json:"secure,omitempty"`
}

type BackupStorageGCSSpec struct {
	Bucket             string                `json:"bucket,omitempty"`
	Path               string                `json:"path,omitempty"`
	CredentialSelector GCPCredentialSelector `json:"credentialSelector,omitempty"`
}

type EtcdClusterStatus struct {
	Ready                   bool             `json:"ready"`
	Phase                   EtcdClusterPhase `json:"phase,omitempty"`
	Members                 []MemberStatus   `json:"members,omitempty"`
	LastReadyTransitionTime *metav1.Time     `json:"lastReadyTransitionTime,omitempty"`
	LastDefragmentTime      *metav1.Time     `json:"lastDefragmentTime,omitempty"`
	ClientEndpoint          string           `json:"clientEndpoint,omitempty"`
	ClientCertSecretName    string           `json:"clientCertSecretName,omitempty"`
	Backup                  *BackupStatus    `json:"backup,omitempty"`
	RestoreFrom             string           `json:"restoreFrom,omitempty"`
}

type MemberStatus struct {
	Id      int64  `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	PodName string `json:"podName,omitempty"`
	Leader  bool   `json:"leader,omitempty"`
	Version string `json:"version,omitempty"`
}

type BackupStatus struct {
	Succeeded         bool                  `json:"succeeded,omitempty"`
	LastSucceededTime *metav1.Time          `json:"lastSucceededTime,omitempty"`
	History           []BackupStatusHistory `json:"backupStatusHistory,omitempty"`
}

type BackupStatusHistory struct {
	Succeeded    bool         `json:"succeeded,omitempty"`
	ExecuteTime  *metav1.Time `json:"executeTime,omitempty"`
	Path         string       `json:"path,omitempty"`
	EtcdVersion  string       `json:"etcdVersion,omitempty"`
	EtcdRevision int64        `json:"etcdRevision,omitempty"`
	Message      string       `json:"message,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EtcdClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []EtcdCluster `json:"items"`
}
