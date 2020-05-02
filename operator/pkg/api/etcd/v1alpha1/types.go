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
)

type StorageType string

const (
	StorageMemory     StorageType = "memory"
	StoragePersistent StorageType = "persistent"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
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
	Members            int    `json:"members"`
	Version            string `json:"version"`
	DefragmentSchedule string `json:"defragmentSchedule"`
}

type EtcdClusterStatus struct {
	Ready                   bool             `json:"ready"`
	Phase                   EtcdClusterPhase `json:"phase,omitempty"`
	Members                 []MemberStatus   `json:"members,omitempty"`
	LastReadyTransitionTime *metav1.Time     `json:"lastReadyTransitionTime,omitempty"`
	LastDefragmentTime      *metav1.Time     `json:"lastDefragmentTime,omitempty"`
	ClientEndpoint          string           `json:"clientEndpoint,omitempty"`
	ClientCertSecretName    string           `json:"clientCertSecretName,omitempty"`
}

type MemberStatus struct {
	Id      int64  `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	PodName string `json:"podName,omitempty"`
	Leader  bool   `json:"leader,omitempty"`
	Version string `json:"version,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EtcdClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []EtcdCluster `json:"items"`
}
