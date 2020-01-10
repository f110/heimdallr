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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BackendSpec defines the desired state of Backend
type BackendSpec struct {
	FQDN          string       `json:"fqdn,omitempty"` // If fqdn is set, ignore a layer-style naming.
	Layer         string       `json:"layer,omitempty"`
	Upstream      string       `json:"upstream,omitempty"`
	Webhook       string       `json:"webhook,omitempty"`
	WebhookPath   []string     `json:"webhookPath,omitempty"`
	AllowRootUser bool         `json:"allowRootUser,omitempty"`
	Agent         bool         `json:"agent,omitempty"`
	DisableAuthn  bool         `json:"disableAuthn,omitempty"`
	Insecure      bool         `json:"insecure,omitempty"`
	Permissions   []Permission `json:"permissions,omitempty"`
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
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true

// Backend is the Schema for the backends API
type Backend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendSpec   `json:"spec,omitempty"`
	Status BackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BackendList contains a list of Backend
type BackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Backend `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Backend{}, &BackendList{})
}
