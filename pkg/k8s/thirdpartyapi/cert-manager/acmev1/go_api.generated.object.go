package acmev1

import (
	metav1_1 "go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/cert-manager/metav1"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const GroupName = "cert-manager.io."

var (
	GroupVersion       = metav1.GroupVersion{Group: GroupName, Version: "v1"}
	SchemeBuilder      = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme        = SchemeBuilder.AddToScheme
	SchemaGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1"}
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemaGroupVersion,
		&Challenge{},
		&ChallengeList{},
		&Order{},
		&OrderList{},
	)
	metav1.AddToGroupVersion(scheme, SchemaGroupVersion)
	return nil
}

type ACMEChallengeType string

const (
	ACMEChallengeTypeHttp01 ACMEChallengeType = "HTTP-01"
	ACMEChallengeTypeDns01  ACMEChallengeType = "DNS-01"
)

type AzureDNSEnvironment string

const (
	AzureDNSEnvironmentAzurePublicCloud       AzureDNSEnvironment = "AzurePublicCloud"
	AzureDNSEnvironmentAzureChinaCloud        AzureDNSEnvironment = "AzureChinaCloud"
	AzureDNSEnvironmentAzureGermanCloud       AzureDNSEnvironment = "AzureGermanCloud"
	AzureDNSEnvironmentAzureUSGovernmentCloud AzureDNSEnvironment = "AzureUSGovernmentCloud"
)

type HMACKeyAlgorithm string

const (
	HMACKeyAlgorithmHs256 HMACKeyAlgorithm = "HS256"
	HMACKeyAlgorithmHs384 HMACKeyAlgorithm = "HS384"
	HMACKeyAlgorithmHs512 HMACKeyAlgorithm = "HS512"
)

type State string

const (
	StateUNKNOWN    State = "UNKNOWN"
	StateValid      State = "valid"
	StateReady      State = "ready"
	StatePending    State = "pending"
	StateProcessing State = "processing"
	StateInvalid    State = "invalid"
	StateExpired    State = "expired"
	StateErrored    State = "errored"
)

type ACMEAuthorization struct {
	// URL is the URL of the Authorization that must be completed
	URL string `json:"url"`
	// Identifier is the DNS name to be validated as part of this authorization
	Identifier string `json:"identifier,omitempty"`
	// Wildcard will be true if this authorization is for a wildcard DNS name.
	// If this is true, the identifier will be the *non-wildcard* version of
	// the DNS name.
	// For example, if '*.example.com' is the DNS name being validated, this
	// field will be 'true' and the 'identifier' field will be 'example.com'.
	Wildcard bool `json:"wildcard,omitempty"`
	// InitialState is the initial state of the ACME authorization when first
	// fetched from the ACME server.
	// If an Authorization is already 'valid', the Order controller will not
	// create a Challenge resource for the authorization. This will occur when
	// working with an ACME server that enables 'authz reuse' (such as Let's
	// Encrypt's production endpoint).
	// If not set and 'identifier' is set, the state is assumed to be pending
	// and a Challenge will be created.
	InitialState State `json:"initialState,omitempty"`
	// Challenges specifies the challenge types offered by the ACME server.
	// One of these challenge types will be selected when validating the DNS
	// name and an appropriate Challenge resource will be created to perform
	// the ACME challenge process.
	Challenges []ACMEChallenge `json:"challenges"`
}

func (in *ACMEAuthorization) DeepCopyInto(out *ACMEAuthorization) {
	*out = *in
	if in.Challenges != nil {
		l := make([]ACMEChallenge, len(in.Challenges))
		for i := range in.Challenges {
			in.Challenges[i].DeepCopyInto(&l[i])
		}
		out.Challenges = l
	}
}

func (in *ACMEAuthorization) DeepCopy() *ACMEAuthorization {
	if in == nil {
		return nil
	}
	out := new(ACMEAuthorization)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallenge struct {
	// URL is the URL of this challenge. It can be used to retrieve additional
	// metadata about the Challenge from the ACME server.
	URL string `json:"url"`
	// Token is the token that must be presented for this challenge.
	// This is used to compute the 'key' that must also be presented.
	Token string `json:"token"`
	// Type is the type of challenge being offered, e.g. 'http-01', 'dns-01',
	// 'tls-sni-01', etc.
	// This is the raw value retrieved from the ACME server.
	// Only 'http-01' and 'dns-01' are supported by cert-manager, other values
	// will be ignored.
	Type string `json:"type"`
}

func (in *ACMEChallenge) DeepCopyInto(out *ACMEChallenge) {
	*out = *in
}

func (in *ACMEChallenge) DeepCopy() *ACMEChallenge {
	if in == nil {
		return nil
	}
	out := new(ACMEChallenge)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolver struct {
	// Selector selects a set of DNSNames on the Certificate resource that
	// should be solved using this challenge solver.
	// If not specified, the solver will be treated as the 'default' solver
	// with the lowest priority, i.e. if any other solver has a more specific
	// match, it will be used instead.
	Selector *CertificateDNSNameSelector `json:"selector,omitempty"`
	// Configures cert-manager to attempt to complete authorizations by
	// performing the Http01 challenge flow.
	// It is not possible to obtain certificates for wildcard domain names
	// (e.g. `*.example.com`) using the HTTP01 challenge mechanism.
	HTTP01 *ACMEChallengeSolverHTTP01 `json:"http01,omitempty"`
	// Configures cert-manager to attempt to complete authorizations by
	// performing the Dns01 challenge flow.
	DNS01 *ACMEChallengeSolverDNS01 `json:"dns01,omitempty"`
}

func (in *ACMEChallengeSolver) DeepCopyInto(out *ACMEChallengeSolver) {
	*out = *in
	if in.Selector != nil {
		in, out := &in.Selector, &out.Selector
		*out = new(CertificateDNSNameSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.HTTP01 != nil {
		in, out := &in.HTTP01, &out.HTTP01
		*out = new(ACMEChallengeSolverHTTP01)
		(*in).DeepCopyInto(*out)
	}
	if in.DNS01 != nil {
		in, out := &in.DNS01, &out.DNS01
		*out = new(ACMEChallengeSolverDNS01)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEChallengeSolver) DeepCopy() *ACMEChallengeSolver {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolver)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverDNS01 struct {
	// CNAMEStrategy configures how the DNS01 provider should handle CNAME
	// records when found in DNS zones.
	CNAMEStrategy string `json:"cnameStrategy"`
	// Use the Akamai DNS zone management API to manage DNS01 challenge records.
	Akamai *ACMEIssuerDNS01ProviderAkamai `json:"akamai,omitempty"`
	// Use the Google Cloud DNS API to manage DNS01 challenge records.
	CloudDNS *ACMEIssuerDNS01ProviderCloudDNS `json:"cloudDNS,omitempty"`
	// Use the Cloudflare API to manage DNS01 challenge records.
	Cloudflare *ACMEIssuerDNS01ProviderCloudflare `json:"cloudflare,omitempty"`
	// Use the AWS Route53 API to manage DNS01 challenge records.
	Route53 *ACMEIssuerDNS01ProviderRoute53 `json:"route53,omitempty"`
	// Use the Microsoft Azure DNS API to manage DNS01 challenge records.
	AzureDNS *ACMEIssuerDNS01ProviderAzureDNS `json:"azureDNS,omitempty"`
	// Use the DigitalOcean DNS API to manage DNS01 challenge records.
	DigitalOcean *ACMEIssuerDNS01ProviderDigitalOcean `json:"digitalocean,omitempty"`
	// Use the 'ACME DNS' (https://github.com/joohoi/acme-dns) API to manage
	// DNS01 challenge records.
	AcmeDNS *ACMEIssuerDNS01ProviderAcmeDNS `json:"acmeDNS,omitempty"`
	// Use Rfc2136 ("Dynamic Updates in the Domain Name System") (https://datatracker.ietf.org/doc/rfc2136/)
	// to manage DNS01 challenge records.
	RFC2136 *ACMEIssuerDNS01ProviderRFC2136 `json:"rfc2136,omitempty"`
	// Configure an external webhook based DNS01 challenge solver to manage
	// DNS01 challenge records.
	Webhook *ACMEIssuerDNS01ProviderWebhook `json:"webhook,omitempty"`
}

func (in *ACMEChallengeSolverDNS01) DeepCopyInto(out *ACMEChallengeSolverDNS01) {
	*out = *in
	if in.Akamai != nil {
		in, out := &in.Akamai, &out.Akamai
		*out = new(ACMEIssuerDNS01ProviderAkamai)
		(*in).DeepCopyInto(*out)
	}
	if in.CloudDNS != nil {
		in, out := &in.CloudDNS, &out.CloudDNS
		*out = new(ACMEIssuerDNS01ProviderCloudDNS)
		(*in).DeepCopyInto(*out)
	}
	if in.Cloudflare != nil {
		in, out := &in.Cloudflare, &out.Cloudflare
		*out = new(ACMEIssuerDNS01ProviderCloudflare)
		(*in).DeepCopyInto(*out)
	}
	if in.Route53 != nil {
		in, out := &in.Route53, &out.Route53
		*out = new(ACMEIssuerDNS01ProviderRoute53)
		(*in).DeepCopyInto(*out)
	}
	if in.AzureDNS != nil {
		in, out := &in.AzureDNS, &out.AzureDNS
		*out = new(ACMEIssuerDNS01ProviderAzureDNS)
		(*in).DeepCopyInto(*out)
	}
	if in.DigitalOcean != nil {
		in, out := &in.DigitalOcean, &out.DigitalOcean
		*out = new(ACMEIssuerDNS01ProviderDigitalOcean)
		(*in).DeepCopyInto(*out)
	}
	if in.AcmeDNS != nil {
		in, out := &in.AcmeDNS, &out.AcmeDNS
		*out = new(ACMEIssuerDNS01ProviderAcmeDNS)
		(*in).DeepCopyInto(*out)
	}
	if in.RFC2136 != nil {
		in, out := &in.RFC2136, &out.RFC2136
		*out = new(ACMEIssuerDNS01ProviderRFC2136)
		(*in).DeepCopyInto(*out)
	}
	if in.Webhook != nil {
		in, out := &in.Webhook, &out.Webhook
		*out = new(ACMEIssuerDNS01ProviderWebhook)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEChallengeSolverDNS01) DeepCopy() *ACMEChallengeSolverDNS01 {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverDNS01)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01 struct {
	// The ingress based HTTP01 challenge solver will solve challenges by
	// creating or modifying Ingress resources in order to route requests for
	// '/.well-known/acme-challenge/XYZ' to 'challenge solver' pods that are
	// provisioned by cert-manager for each Challenge to be completed.
	Ingress *ACMEChallengeSolverHTTP01Ingress `json:"ingress,omitempty"`
	// The Gateway API is a sig-network community API that models service networking
	// in Kubernetes (https://gateway-api.sigs.k8s.io/). The Gateway solver will
	// create HTTPRoutes with the specified labels in the same namespace as the challenge.
	// This solver is experimental, and fields / behaviour may change in the future.
	GatewayHTTPRoute *ACMEChallengeSolverHTTP01GatewayHTTPRoute `json:"gatewayHTTPRoute,omitempty"`
}

func (in *ACMEChallengeSolverHTTP01) DeepCopyInto(out *ACMEChallengeSolverHTTP01) {
	*out = *in
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = new(ACMEChallengeSolverHTTP01Ingress)
		(*in).DeepCopyInto(*out)
	}
	if in.GatewayHTTPRoute != nil {
		in, out := &in.GatewayHTTPRoute, &out.GatewayHTTPRoute
		*out = new(ACMEChallengeSolverHTTP01GatewayHTTPRoute)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEChallengeSolverHTTP01) DeepCopy() *ACMEChallengeSolverHTTP01 {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01GatewayHTTPRoute struct {
	// Optional service type for Kubernetes solver service. Supported values
	// are NodePort or ClusterIP. If unset, defaults to NodePort.
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
	// The labels that cert-manager will use when creating the temporary
	// HTTPRoute needed for solving the HTTP-01 challenge. These labels
	// must match the label selector of at least one Gateway.
	Labels map[string]string `json:"labels,omitempty"`
}

func (in *ACMEChallengeSolverHTTP01GatewayHTTPRoute) DeepCopyInto(out *ACMEChallengeSolverHTTP01GatewayHTTPRoute) {
	*out = *in
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
}

func (in *ACMEChallengeSolverHTTP01GatewayHTTPRoute) DeepCopy() *ACMEChallengeSolverHTTP01GatewayHTTPRoute {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01GatewayHTTPRoute)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01Ingress struct {
	// Optional service type for Kubernetes solver service. Supported values
	// are NodePort or ClusterIP. If unset, defaults to NodePort.
	ServiceType corev1.ServiceType `json:"serviceType,omitempty"`
	// The ingress class to use when creating Ingress resources to solve ACME
	// challenges that use this challenge solver.
	// Only one of 'class' or 'name' may be specified.
	Class string `json:"class,omitempty"`
	// The name of the ingress resource that should have ACME challenge solving
	// routes inserted into it in order to solve HTTP01 challenges.
	// This is typically used in conjunction with ingress controllers like
	// ingress-gce, which maintains a 1:1 mapping between external IPs and
	// ingress resources.
	Name string `json:"name,omitempty"`
	// Optional pod template used to configure the ACME challenge solver pods
	// used for HTTP01 challenges.
	PodTemplate *ACMEChallengeSolverHTTP01IngressPodTemplate `json:"podTemplate,omitempty"`
	// Optional ingress template used to configure the ACME challenge solver
	// ingress used for HTTP01 challenges.
	IngressTemplate *ACMEChallengeSolverHTTP01IngressTemplate `json:"ingressTemplate,omitempty"`
}

func (in *ACMEChallengeSolverHTTP01Ingress) DeepCopyInto(out *ACMEChallengeSolverHTTP01Ingress) {
	*out = *in
	if in.PodTemplate != nil {
		in, out := &in.PodTemplate, &out.PodTemplate
		*out = new(ACMEChallengeSolverHTTP01IngressPodTemplate)
		(*in).DeepCopyInto(*out)
	}
	if in.IngressTemplate != nil {
		in, out := &in.IngressTemplate, &out.IngressTemplate
		*out = new(ACMEChallengeSolverHTTP01IngressTemplate)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEChallengeSolverHTTP01Ingress) DeepCopy() *ACMEChallengeSolverHTTP01Ingress {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01Ingress)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01IngressObjectMeta struct {
	// Annotations that should be added to the created ACME HTTP01 solver ingress.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Labels that should be added to the created ACME HTTP01 solver ingress.
	Labels map[string]string `json:"labels,omitempty"`
}

func (in *ACMEChallengeSolverHTTP01IngressObjectMeta) DeepCopyInto(out *ACMEChallengeSolverHTTP01IngressObjectMeta) {
	*out = *in
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
}

func (in *ACMEChallengeSolverHTTP01IngressObjectMeta) DeepCopy() *ACMEChallengeSolverHTTP01IngressObjectMeta {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01IngressObjectMeta)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01IngressPodObjectMeta struct {
	// Annotations that should be added to the create ACME HTTP01 solver pods.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Labels that should be added to the created ACME HTTP01 solver pods.
	Labels map[string]string `json:"labels,omitempty"`
}

func (in *ACMEChallengeSolverHTTP01IngressPodObjectMeta) DeepCopyInto(out *ACMEChallengeSolverHTTP01IngressPodObjectMeta) {
	*out = *in
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
}

func (in *ACMEChallengeSolverHTTP01IngressPodObjectMeta) DeepCopy() *ACMEChallengeSolverHTTP01IngressPodObjectMeta {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01IngressPodObjectMeta)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01IngressPodSpec struct {
	// NodeSelector is a selector which must be true for the pod to fit on a node.
	// Selector which must match a node's labels for the pod to be scheduled on that node.
	// More info: https://kubernetes.io/docs/concepts/configuration/assign-pod-node/
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// If specified, the pod's scheduling constraints
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// If specified, the pod's tolerations.
	Tolerations []corev1.Toleration `json:"tolerations"`
	// If specified, the pod's priorityClassName.
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// If specified, the pod's service account
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
}

func (in *ACMEChallengeSolverHTTP01IngressPodSpec) DeepCopyInto(out *ACMEChallengeSolverHTTP01IngressPodSpec) {
	*out = *in
	if in.NodeSelector != nil {
		in, out := &in.NodeSelector, &out.NodeSelector
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
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
}

func (in *ACMEChallengeSolverHTTP01IngressPodSpec) DeepCopy() *ACMEChallengeSolverHTTP01IngressPodSpec {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01IngressPodSpec)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01IngressPodTemplate struct {
	// ObjectMeta overrides for the pod used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or annotations overlap with in-built values, the values here
	// will override the in-built values.
	ACMEChallengeSolverHTTP01IngressPodObjectMeta ACMEChallengeSolverHTTP01IngressPodObjectMeta `json:"metadata"`
	// PodSpec defines overrides for the HTTP01 challenge solver pod.
	// Only the 'priorityClassName', 'nodeSelector', 'affinity',
	// 'serviceAccountName' and 'tolerations' fields are supported currently.
	// All other fields will be ignored.
	Spec ACMEChallengeSolverHTTP01IngressPodSpec `json:"spec"`
}

func (in *ACMEChallengeSolverHTTP01IngressPodTemplate) DeepCopyInto(out *ACMEChallengeSolverHTTP01IngressPodTemplate) {
	*out = *in
	in.ACMEChallengeSolverHTTP01IngressPodObjectMeta.DeepCopyInto(&out.ACMEChallengeSolverHTTP01IngressPodObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *ACMEChallengeSolverHTTP01IngressPodTemplate) DeepCopy() *ACMEChallengeSolverHTTP01IngressPodTemplate {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01IngressPodTemplate)
	in.DeepCopyInto(out)
	return out
}

type ACMEChallengeSolverHTTP01IngressTemplate struct {
	// ObjectMeta overrides for the ingress used to solve HTTP01 challenges.
	// Only the 'labels' and 'annotations' fields may be set.
	// If labels or annotations overlap with in-built values, the values here
	// will override the in-built values.
	ACMEChallengeSolverHTTP01IngressObjectMeta ACMEChallengeSolverHTTP01IngressObjectMeta `json:"metadata"`
}

func (in *ACMEChallengeSolverHTTP01IngressTemplate) DeepCopyInto(out *ACMEChallengeSolverHTTP01IngressTemplate) {
	*out = *in
	in.ACMEChallengeSolverHTTP01IngressObjectMeta.DeepCopyInto(&out.ACMEChallengeSolverHTTP01IngressObjectMeta)
}

func (in *ACMEChallengeSolverHTTP01IngressTemplate) DeepCopy() *ACMEChallengeSolverHTTP01IngressTemplate {
	if in == nil {
		return nil
	}
	out := new(ACMEChallengeSolverHTTP01IngressTemplate)
	in.DeepCopyInto(out)
	return out
}

type ACMEExternalAccountBinding struct {
	// keyID is the ID of the CA key that the External Account is bound to.
	KeyID string `json:"keyID"`
	// keySecretRef is a Secret Key Selector referencing a data item in a Kubernetes
	// Secret which holds the symmetric MAC key of the External Account Binding.
	// The `key` is the index string that is paired with the key data in the
	// Secret and should not be confused with the key data itself, or indeed with
	// the External Account Binding keyID above.
	// The secret key stored in the Secret **must** be un-padded, base64 URL
	// encoded data.
	Key metav1_1.SecretKeySelector `json:"keySecretRef"`
	// Deprecated: keyAlgorithm field exists for historical compatibility
	// reasons and should not be used. The algorithm is now hardcoded to HS256
	// in golang/x/crypto/acme.
	KeyAlgorithm HMACKeyAlgorithm `json:"keyAlgorithm,omitempty"`
}

func (in *ACMEExternalAccountBinding) DeepCopyInto(out *ACMEExternalAccountBinding) {
	*out = *in
	in.Key.DeepCopyInto(&out.Key)
}

func (in *ACMEExternalAccountBinding) DeepCopy() *ACMEExternalAccountBinding {
	if in == nil {
		return nil
	}
	out := new(ACMEExternalAccountBinding)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuer struct {
	// Email is the email address to be associated with the ACME account.
	// This field is optional, but it is strongly recommended to be set.
	// It will be used to contact you in case of issues with your account or
	// certificates, including expiry notification emails.
	// This field may be updated after the account is initially registered.
	Email string `json:"email,omitempty"`
	// Server is the URL used to access the ACME server's 'directory' endpoint.
	// For example, for Let's Encrypt's staging endpoint, you would use:
	// "https://acme-staging-v02.api.letsencrypt.org/directory".
	// Only ACME v2 endpoints (i.e. RFC 8555) are supported.
	Server string `json:"server"`
	// PreferredChain is the chain to use if the ACME server outputs multiple.
	// PreferredChain is no guarantee that this one gets delivered by the ACME
	// endpoint.
	// For example, for Let's Encrypt's DST crosssign you would use:
	// "DST Root CA X3" or "ISRG Root X1" for the newer Let's Encrypt root CA.
	// This value picks the first certificate bundle in the ACME alternative
	// chains that has a certificate with this value as its issuer's CN
	PreferredChain string `json:"preferredChain"`
	// Enables or disables validation of the ACME server TLS certificate.
	// If true, requests to the ACME server will not have their TLS certificate
	// validated (i.e. insecure connections will be allowed).
	// Only enable this option in development environments.
	// The cert-manager system installed roots will be used to verify connections
	// to the ACME server if this is false.
	// Defaults to false.
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`
	// ExternalAccountBinding is a reference to a CA external account of the ACME
	// server.
	// If set, upon registration cert-manager will attempt to associate the given
	// external account credentials with the registered ACME account.
	ExternalAccountBinding *ACMEExternalAccountBinding `json:"externalAccountBinding,omitempty"`
	// PrivateKey is the name of a Kubernetes Secret resource that will be used to
	// store the automatically generated ACME account private key.
	// Optionally, a `key` may be specified to select a specific entry within
	// the named Secret resource.
	// If `key` is not specified, a default of `tls.key` will be used.
	PrivateKey metav1_1.SecretKeySelector `json:"privateKeySecretRef"`
	// Solvers is a list of challenge solvers that will be used to solve
	// ACME challenges for the matching domains.
	// Solver configurations must be provided in order to obtain certificates
	// from an ACME server.
	// For more information, see: https://cert-manager.io/docs/configuration/acme/
	Solvers []ACMEChallengeSolver `json:"solvers"`
	// Enables or disables generating a new ACME account key.
	// If true, the Issuer resource will *not* request a new account but will expect
	// the account key to be supplied via an existing secret.
	// If false, the cert-manager system will generate a new ACME account key
	// for the Issuer.
	// Defaults to false.
	DisableAccountKeyGeneration bool `json:"disableAccountKeyGeneration,omitempty"`
	// Enables requesting a Not After date on certificates that matches the
	// duration of the certificate. This is not supported by all ACME servers
	// like Let's Encrypt. If set to true when the ACME server does not support
	// it it will create an error on the Order.
	// Defaults to false.
	EnableDurationFeature bool `json:"enableDurationFeature,omitempty"`
}

func (in *ACMEIssuer) DeepCopyInto(out *ACMEIssuer) {
	*out = *in
	if in.ExternalAccountBinding != nil {
		in, out := &in.ExternalAccountBinding, &out.ExternalAccountBinding
		*out = new(ACMEExternalAccountBinding)
		(*in).DeepCopyInto(*out)
	}
	in.PrivateKey.DeepCopyInto(&out.PrivateKey)
	if in.Solvers != nil {
		l := make([]ACMEChallengeSolver, len(in.Solvers))
		for i := range in.Solvers {
			in.Solvers[i].DeepCopyInto(&l[i])
		}
		out.Solvers = l
	}
}

func (in *ACMEIssuer) DeepCopy() *ACMEIssuer {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuer)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderAcmeDNS struct {
	Host          string                     `json:"host"`
	AccountSecret metav1_1.SecretKeySelector `json:"accountSecretRef"`
}

func (in *ACMEIssuerDNS01ProviderAcmeDNS) DeepCopyInto(out *ACMEIssuerDNS01ProviderAcmeDNS) {
	*out = *in
	in.AccountSecret.DeepCopyInto(&out.AccountSecret)
}

func (in *ACMEIssuerDNS01ProviderAcmeDNS) DeepCopy() *ACMEIssuerDNS01ProviderAcmeDNS {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderAcmeDNS)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderAkamai struct {
	ServiceConsumerDomain string                     `json:"serviceConsumerDomain"`
	ClientToken           metav1_1.SecretKeySelector `json:"clientTokenSecretRef"`
	ClientSecret          metav1_1.SecretKeySelector `json:"clientSecretSecretRef"`
	AccessToken           metav1_1.SecretKeySelector `json:"accessTokenSecretRef"`
}

func (in *ACMEIssuerDNS01ProviderAkamai) DeepCopyInto(out *ACMEIssuerDNS01ProviderAkamai) {
	*out = *in
	in.ClientToken.DeepCopyInto(&out.ClientToken)
	in.ClientSecret.DeepCopyInto(&out.ClientSecret)
	in.AccessToken.DeepCopyInto(&out.AccessToken)
}

func (in *ACMEIssuerDNS01ProviderAkamai) DeepCopy() *ACMEIssuerDNS01ProviderAkamai {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderAkamai)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderAzureDNS struct {
	// if both this and ClientSecret are left unset MSI will be used
	ClientID string `json:"clientID,omitempty"`
	// if both this and ClientID are left unset MSI will be used
	ClientSecret *metav1_1.SecretKeySelector `json:"clientSecretSecretRef,omitempty"`
	// ID of the Azure subscription
	SubscriptionID string `json:"subscriptionID"`
	// when specifying ClientID and ClientSecret then this field is also needed
	TenantID string `json:"tenantID,omitempty"`
	// resource group the DNS zone is located in
	ResourceGroupName string `json:"resourceGroupName"`
	// name of the DNS zone that should be used
	HostedZoneName string `json:"hostedZoneName,omitempty"`
	// name of the Azure environment (default AzurePublicCloud)
	Environment AzureDNSEnvironment `json:"environment,omitempty"`
	// managed identity configuration, can not be used at the same time as clientID, clientSecretSecretRef or tenantID
	ManagedIdentity *AzureManagedIdentity `json:"managedIdentity,omitempty"`
}

func (in *ACMEIssuerDNS01ProviderAzureDNS) DeepCopyInto(out *ACMEIssuerDNS01ProviderAzureDNS) {
	*out = *in
	if in.ClientSecret != nil {
		in, out := &in.ClientSecret, &out.ClientSecret
		*out = new(metav1_1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.ManagedIdentity != nil {
		in, out := &in.ManagedIdentity, &out.ManagedIdentity
		*out = new(AzureManagedIdentity)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEIssuerDNS01ProviderAzureDNS) DeepCopy() *ACMEIssuerDNS01ProviderAzureDNS {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderAzureDNS)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderCloudDNS struct {
	ServiceAccount *metav1_1.SecretKeySelector `json:"serviceAccountSecretRef,omitempty"`
	Project        string                      `json:"project"`
	// HostedZoneName is an optional field that tells cert-manager in which
	// Cloud DNS zone the challenge record has to be created.
	// If left empty cert-manager will automatically choose a zone.
	HostedZoneName string `json:"hostedZoneName,omitempty"`
}

func (in *ACMEIssuerDNS01ProviderCloudDNS) DeepCopyInto(out *ACMEIssuerDNS01ProviderCloudDNS) {
	*out = *in
	if in.ServiceAccount != nil {
		in, out := &in.ServiceAccount, &out.ServiceAccount
		*out = new(metav1_1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEIssuerDNS01ProviderCloudDNS) DeepCopy() *ACMEIssuerDNS01ProviderCloudDNS {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderCloudDNS)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderCloudflare struct {
	// Email of the account, only required when using API key based authentication.
	Email string `json:"email,omitempty"`
	// API key to use to authenticate with Cloudflare.
	// Note: using an API token to authenticate is now the recommended method
	// as it allows greater control of permissions.
	APIKey *metav1_1.SecretKeySelector `json:"apiKeySecretRef,omitempty"`
	// API token used to authenticate with Cloudflare.
	APIToken *metav1_1.SecretKeySelector `json:"apiTokenSecretRef,omitempty"`
}

func (in *ACMEIssuerDNS01ProviderCloudflare) DeepCopyInto(out *ACMEIssuerDNS01ProviderCloudflare) {
	*out = *in
	if in.APIKey != nil {
		in, out := &in.APIKey, &out.APIKey
		*out = new(metav1_1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.APIToken != nil {
		in, out := &in.APIToken, &out.APIToken
		*out = new(metav1_1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEIssuerDNS01ProviderCloudflare) DeepCopy() *ACMEIssuerDNS01ProviderCloudflare {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderCloudflare)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderDigitalOcean struct {
	Token metav1_1.SecretKeySelector `json:"tokenSecretRef"`
}

func (in *ACMEIssuerDNS01ProviderDigitalOcean) DeepCopyInto(out *ACMEIssuerDNS01ProviderDigitalOcean) {
	*out = *in
	in.Token.DeepCopyInto(&out.Token)
}

func (in *ACMEIssuerDNS01ProviderDigitalOcean) DeepCopy() *ACMEIssuerDNS01ProviderDigitalOcean {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderDigitalOcean)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderRFC2136 struct {
	// The IP address or hostname of an authoritative DNS server supporting
	// RFC2136 in the form host:port. If the host is an IPv6 address it must be
	// enclosed in square brackets (e.g [2001:db8::1]) ; port is optional.
	// This field is required.
	Nameserver string `json:"nameserver"`
	// The name of the secret containing the TSIG value.
	// If “tsigKeyName“ is defined, this field is required.
	TSIGSecret *metav1_1.SecretKeySelector `json:"tsigSecretSecretRef,omitempty"`
	// The TSIG Key name configured in the DNS.
	// If “tsigSecretSecretRef“ is defined, this field is required.
	TSIGKeyName string `json:"tsigKeyName,omitempty"`
	// The TSIG Algorithm configured in the DNS supporting RFC2136. Used only
	// when “tsigSecretSecretRef“ and “tsigKeyName“ are defined.
	// Supported values are (case-insensitive): “HMACMD5“ (default),
	// “HMACSHA1“, “HMACSHA256“ or “HMACSHA512“.
	TSIGAlgorithm string `json:"tsigAlgorithm,omitempty"`
}

func (in *ACMEIssuerDNS01ProviderRFC2136) DeepCopyInto(out *ACMEIssuerDNS01ProviderRFC2136) {
	*out = *in
	if in.TSIGSecret != nil {
		in, out := &in.TSIGSecret, &out.TSIGSecret
		*out = new(metav1_1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEIssuerDNS01ProviderRFC2136) DeepCopy() *ACMEIssuerDNS01ProviderRFC2136 {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderRFC2136)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderRoute53 struct {
	// The AccessKeyID is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
	// see: https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	AccessKeyID string `json:"accessKeyID,omitempty"`
	// The SecretAccessKey is used for authentication. If not set we fall-back to using env vars, shared credentials file or AWS Instance metadata
	// https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials
	SecretAccessKey metav1_1.SecretKeySelector `json:"secretAccessKeySecretRef"`
	// Role is a Role ARN which the Route53 provider will assume using either the explicit credentials AccessKeyID/SecretAccessKey
	// or the inferred credentials from environment variables, shared credentials file or AWS Instance metadata
	Role string `json:"role,omitempty"`
	// If set, the provider will manage only this zone in Route53 and will not do an lookup using the route53:ListHostedZonesByName api call.
	HostedZoneID string `json:"hostedZoneID,omitempty"`
	// Always set the region when using AccessKeyID and SecretAccessKey
	Region string `json:"region"`
}

func (in *ACMEIssuerDNS01ProviderRoute53) DeepCopyInto(out *ACMEIssuerDNS01ProviderRoute53) {
	*out = *in
	in.SecretAccessKey.DeepCopyInto(&out.SecretAccessKey)
}

func (in *ACMEIssuerDNS01ProviderRoute53) DeepCopy() *ACMEIssuerDNS01ProviderRoute53 {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderRoute53)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerDNS01ProviderWebhook struct {
	// The API group name that should be used when POSTing ChallengePayload
	// resources to the webhook apiserver.
	// This should be the same as the GroupName specified in the webhook
	// provider implementation.
	GroupName string `json:"groupName"`
	// The name of the solver to use, as defined in the webhook provider
	// implementation.
	// This will typically be the name of the provider, e.g. 'cloudflare'.
	SolverName string `json:"solverName"`
	// Additional configuration that should be passed to the webhook apiserver
	// when challenges are processed.
	// This can contain arbitrary JSON data.
	// Secret values should not be specified in this stanza.
	// If secret values are needed (e.g. credentials for a DNS service), you
	// should use a SecretKeySelector to reference a Secret resource.
	// For details on the schema of this field, consult the webhook provider
	// implementation's documentation.
	Config *apiextensionsv1.JSON `json:"config,omitempty"`
}

func (in *ACMEIssuerDNS01ProviderWebhook) DeepCopyInto(out *ACMEIssuerDNS01ProviderWebhook) {
	*out = *in
	if in.Config != nil {
		in, out := &in.Config, &out.Config
		*out = new(apiextensionsv1.JSON)
		(*in).DeepCopyInto(*out)
	}
}

func (in *ACMEIssuerDNS01ProviderWebhook) DeepCopy() *ACMEIssuerDNS01ProviderWebhook {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerDNS01ProviderWebhook)
	in.DeepCopyInto(out)
	return out
}

type ACMEIssuerStatus struct {
	// URI is the unique account identifier, which can also be used to retrieve
	// account details from the CA
	URI string `json:"uri,omitempty"`
	// LastRegisteredEmail is the email associated with the latest registered
	// ACME account, in order to track changes made to registered account
	// associated with the  Issuer
	LastRegisteredEmail string `json:"lastRegisteredEmail,omitempty"`
}

func (in *ACMEIssuerStatus) DeepCopyInto(out *ACMEIssuerStatus) {
	*out = *in
}

func (in *ACMEIssuerStatus) DeepCopy() *ACMEIssuerStatus {
	if in == nil {
		return nil
	}
	out := new(ACMEIssuerStatus)
	in.DeepCopyInto(out)
	return out
}

type AzureManagedIdentity struct {
	// client ID of the managed identity, can not be used at the same time as resourceID
	ClientID string `json:"clientID,omitempty"`
	// resource ID of the managed identity, can not be used at the same time as clientID
	ResourceID string `json:"resourceID,omitempty"`
}

func (in *AzureManagedIdentity) DeepCopyInto(out *AzureManagedIdentity) {
	*out = *in
}

func (in *AzureManagedIdentity) DeepCopy() *AzureManagedIdentity {
	if in == nil {
		return nil
	}
	out := new(AzureManagedIdentity)
	in.DeepCopyInto(out)
	return out
}

type CertificateDNSNameSelector struct {
	// A label selector that is used to refine the set of certificate's that
	// this challenge solver will apply to.
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
	// List of DNSNames that this solver will be used to solve.
	// If specified and a match is found, a dnsNames selector will take
	// precedence over a dnsZones selector.
	// If multiple solvers match with the same dnsNames value, the solver
	// with the most matching labels in matchLabels will be selected.
	// If neither has more matches, the solver defined earlier in the list
	// will be selected.
	DNSNames []string `json:"dnsNames"`
	// List of DNSZones that this solver will be used to solve.
	// The most specific DNS zone match specified here will take precedence
	// over other DNS zone matches, so a solver specifying sys.example.com
	// will be selected over one specifying example.com for the domain
	// www.sys.example.com.
	// If multiple solvers match with the same dnsZones value, the solver
	// with the most matching labels in matchLabels will be selected.
	// If neither has more matches, the solver defined earlier in the list
	// will be selected.
	DNSZones []string `json:"dnsZones"`
}

func (in *CertificateDNSNameSelector) DeepCopyInto(out *CertificateDNSNameSelector) {
	*out = *in
	if in.MatchLabels != nil {
		in, out := &in.MatchLabels, &out.MatchLabels
		*out = make(map[string]string, len(*in))
		for k, v := range *in {
			(*out)[k] = v
		}
	}
	if in.DNSNames != nil {
		t := make([]string, len(in.DNSNames))
		copy(t, in.DNSNames)
		out.DNSNames = t
	}
	if in.DNSZones != nil {
		t := make([]string, len(in.DNSZones))
		copy(t, in.DNSZones)
		out.DNSZones = t
	}
}

func (in *CertificateDNSNameSelector) DeepCopy() *CertificateDNSNameSelector {
	if in == nil {
		return nil
	}
	out := new(CertificateDNSNameSelector)
	in.DeepCopyInto(out)
	return out
}

type Challenge struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              ChallengeSpec   `json:"spec"`
	Status            ChallengeStatus `json:"status"`
}

func (in *Challenge) DeepCopyInto(out *Challenge) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *Challenge) DeepCopy() *Challenge {
	if in == nil {
		return nil
	}
	out := new(Challenge)
	in.DeepCopyInto(out)
	return out
}

func (in *Challenge) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ChallengeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Challenge `json:"items"`
}

func (in *ChallengeList) DeepCopyInto(out *ChallengeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Challenge, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *ChallengeList) DeepCopy() *ChallengeList {
	if in == nil {
		return nil
	}
	out := new(ChallengeList)
	in.DeepCopyInto(out)
	return out
}

func (in *ChallengeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ChallengeSpec struct {
	// The URL of the ACME Challenge resource for this challenge.
	// This can be used to lookup details about the status of this challenge.
	URL string `json:"url"`
	// The URL to the ACME Authorization resource that this
	// challenge is a part of.
	AuthorizationURL string `json:"authorizationURL"`
	// dnsName is the identifier that this challenge is for, e.g. example.com.
	// If the requested DNSName is a 'wildcard', this field MUST be set to the
	// non-wildcard domain, e.g. for `*.example.com`, it must be `example.com`.
	DNSName string `json:"dnsName"`
	// wildcard will be true if this challenge is for a wildcard identifier,
	// for example '*.example.com'.
	Wildcard bool `json:"wildcard"`
	// The type of ACME challenge this resource represents.
	// One of "HTTP-01" or "DNS-01".
	Type ACMEChallengeType `json:"type"`
	// The ACME challenge token for this challenge.
	// This is the raw value returned from the ACME server.
	Token string `json:"token"`
	// The ACME challenge key for this challenge
	// For HTTP01 challenges, this is the value that must be responded with to
	// complete the HTTP01 challenge in the format:
	// `<private key JWK thumbprint>.<key from acme server for challenge>`.
	// For DNS01 challenges, this is the base64 encoded SHA256 sum of the
	// `<private key JWK thumbprint>.<key from acme server for challenge>`
	// text that must be set as the TXT record content.
	Key string `json:"key"`
	// Contains the domain solving configuration that should be used to
	// solve this challenge resource.
	Solver ACMEChallengeSolver `json:"solver"`
	// References a properly configured ACME-type Issuer which should
	// be used to create this Challenge.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Challenge will be marked as failed.
	IssuerRef metav1_1.ObjectReference `json:"issuerRef"`
}

func (in *ChallengeSpec) DeepCopyInto(out *ChallengeSpec) {
	*out = *in
	in.Solver.DeepCopyInto(&out.Solver)
	in.IssuerRef.DeepCopyInto(&out.IssuerRef)
}

func (in *ChallengeSpec) DeepCopy() *ChallengeSpec {
	if in == nil {
		return nil
	}
	out := new(ChallengeSpec)
	in.DeepCopyInto(out)
	return out
}

type ChallengeStatus struct {
	// Used to denote whether this challenge should be processed or not.
	// This field will only be set to true by the 'scheduling' component.
	// It will only be set to false by the 'challenges' controller, after the
	// challenge has reached a final state or timed out.
	// If this field is set to false, the challenge controller will not take
	// any more action.
	Processing bool `json:"processing"`
	// presented will be set to true if the challenge values for this challenge
	// are currently 'presented'.
	// This *does not* imply the self check is passing. Only that the values
	// have been 'submitted' for the appropriate challenge mechanism (i.e. the
	// DNS01 TXT record has been presented, or the HTTP01 configuration has been
	// configured).
	Presented bool `json:"presented"`
	// Contains human readable information on why the Challenge is in the
	// current state.
	Reason string `json:"reason,omitempty"`
	// Contains the current 'state' of the challenge.
	// If not set, the state of the challenge is unknown.
	State State `json:"state,omitempty"`
}

func (in *ChallengeStatus) DeepCopyInto(out *ChallengeStatus) {
	*out = *in
}

func (in *ChallengeStatus) DeepCopy() *ChallengeStatus {
	if in == nil {
		return nil
	}
	out := new(ChallengeStatus)
	in.DeepCopyInto(out)
	return out
}

type Order struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	Spec              OrderSpec   `json:"spec"`
	Status            OrderStatus `json:"status"`
}

func (in *Order) DeepCopyInto(out *Order) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *Order) DeepCopy() *Order {
	if in == nil {
		return nil
	}
	out := new(Order)
	in.DeepCopyInto(out)
	return out
}

func (in *Order) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type OrderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Order `json:"items"`
}

func (in *OrderList) DeepCopyInto(out *OrderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Order, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *OrderList) DeepCopy() *OrderList {
	if in == nil {
		return nil
	}
	out := new(OrderList)
	in.DeepCopyInto(out)
	return out
}

func (in *OrderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type OrderSpec struct {
	// Certificate signing request bytes in DER encoding.
	// This will be used when finalizing the order.
	// This field must be set on the order.
	Request []byte `json:"request,omitempty"`
	// IssuerRef references a properly configured ACME-type Issuer which should
	// be used to create this Order.
	// If the Issuer does not exist, processing will be retried.
	// If the Issuer is not an 'ACME' Issuer, an error will be returned and the
	// Order will be marked as failed.
	IssuerRef metav1_1.ObjectReference `json:"issuerRef"`
	// CommonName is the common name as specified on the DER encoded CSR.
	// If specified, this value must also be present in `dnsNames` or `ipAddresses`.
	// This field must match the corresponding field on the DER encoded CSR.
	CommonName string `json:"commonName,omitempty"`
	// DNSNames is a list of DNS names that should be included as part of the Order
	// validation process.
	// This field must match the corresponding field on the DER encoded CSR.
	DNSNames []string `json:"dnsNames"`
	// IPAddresses is a list of IP addresses that should be included as part of the Order
	// validation process.
	// This field must match the corresponding field on the DER encoded CSR.
	IPAddresses []string `json:"ipAddresses"`
	// Duration is the duration for the not after date for the requested certificate.
	// this is set on order creation as pe the ACME spec.
	Duration *metav1.Duration `json:"duration,omitempty"`
}

func (in *OrderSpec) DeepCopyInto(out *OrderSpec) {
	*out = *in
	in.IssuerRef.DeepCopyInto(&out.IssuerRef)
	if in.DNSNames != nil {
		t := make([]string, len(in.DNSNames))
		copy(t, in.DNSNames)
		out.DNSNames = t
	}
	if in.IPAddresses != nil {
		t := make([]string, len(in.IPAddresses))
		copy(t, in.IPAddresses)
		out.IPAddresses = t
	}
	if in.Duration != nil {
		in, out := &in.Duration, &out.Duration
		*out = new(metav1.Duration)
		(*in).DeepCopyInto(*out)
	}
}

func (in *OrderSpec) DeepCopy() *OrderSpec {
	if in == nil {
		return nil
	}
	out := new(OrderSpec)
	in.DeepCopyInto(out)
	return out
}

type OrderStatus struct {
	// URL of the Order.
	// This will initially be empty when the resource is first created.
	// The Order controller will populate this field when the Order is first processed.
	// This field will be immutable after it is initially set.
	URL string `json:"url,omitempty"`
	// FinalizeURL of the Order.
	// This is used to obtain certificates for this order once it has been completed.
	FinalizeURL string `json:"finalizeURL,omitempty"`
	// Authorizations contains data returned from the ACME server on what
	// authorizations must be completed in order to validate the DNS names
	// specified on the Order.
	Authorizations []ACMEAuthorization `json:"authorizations"`
	// Certificate is a copy of the PEM encoded certificate for this Order.
	// This field will be populated after the order has been successfully
	// finalized with the ACME server, and the order has transitioned to the
	// 'valid' state.
	Certificate []byte `json:"certificate,omitempty"`
	// State contains the current state of this Order resource.
	// States 'success' and 'expired' are 'final'
	State State `json:"state,omitempty"`
	// Reason optionally provides more information about a why the order is in
	// the current state.
	Reason string `json:"reason,omitempty"`
	// FailureTime stores the time that this order failed.
	// This is used to influence garbage collection and back-off.
	FailureTime *metav1.Time `json:"failureTime,omitempty"`
}

func (in *OrderStatus) DeepCopyInto(out *OrderStatus) {
	*out = *in
	if in.Authorizations != nil {
		l := make([]ACMEAuthorization, len(in.Authorizations))
		for i := range in.Authorizations {
			in.Authorizations[i].DeepCopyInto(&l[i])
		}
		out.Authorizations = l
	}
	if in.FailureTime != nil {
		in, out := &in.FailureTime, &out.FailureTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *OrderStatus) DeepCopy() *OrderStatus {
	if in == nil {
		return nil
	}
	out := new(OrderStatus)
	in.DeepCopyInto(out)
	return out
}
