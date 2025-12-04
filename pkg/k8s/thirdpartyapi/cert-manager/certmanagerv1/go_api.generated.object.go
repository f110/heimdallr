package certmanagerv1

import (
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/cert-manager/acmev1"
	metav1_1 "go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/cert-manager/metav1"
	"go.f110.dev/kubeproto/go/apis/metav1"
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
		&Certificate{},
		&CertificateList{},
		&CertificateRequest{},
		&CertificateRequestList{},
		&ClusterIssuer{},
		&ClusterIssuerList{},
		&Issuer{},
		&IssuerList{},
	)
	metav1.AddToGroupVersion(scheme, SchemaGroupVersion)
	return nil
}

type CertificateConditionType string

const (
	CertificateConditionTypeReady   CertificateConditionType = "Ready"
	CertificateConditionTypeIssuing CertificateConditionType = "Issuing"
)

type CertificateRequestConditionType string

const (
	CertificateRequestConditionTypeReady          CertificateRequestConditionType = "Ready"
	CertificateRequestConditionTypeInvalidRequest CertificateRequestConditionType = "InvalidRequest"
	CertificateRequestConditionTypeApproved       CertificateRequestConditionType = "Approved"
	CertificateRequestConditionTypeDenied         CertificateRequestConditionType = "Denied"
)

type IssuerConditionType string

const (
	IssuerConditionTypeReady IssuerConditionType = "Ready"
)

type KeyUsage string

const (
	KeyUsageSigning           KeyUsage = "signing"
	KeyUsageDigitalSignature  KeyUsage = "digital signature"
	KeyUsageContentCommitment KeyUsage = "content commitment"
	KeyUsageKeyEncipherment   KeyUsage = "key encipherment"
	KeyUsageKeyAgreement      KeyUsage = "key agreement"
	KeyUsageDataEncipherment  KeyUsage = "data encipherment"
	KeyUsageCertSign          KeyUsage = "cert sign"
	KeyUsageCrlSign           KeyUsage = "crl sign"
	KeyUsageEncipherOnly      KeyUsage = "encipher only"
	KeyUsageDecipherOnly      KeyUsage = "decipher only"
	KeyUsageAny               KeyUsage = "any"
	KeyUsageServerAuth        KeyUsage = "server auth"
	KeyUsageClientAuth        KeyUsage = "client auth"
	KeyUsageCodeSigning       KeyUsage = "code signing"
	KeyUsageEmailProtection   KeyUsage = "email protection"
	KeyUsageSMime             KeyUsage = "s/mime"
	KeyUsageIpsecEndSystem    KeyUsage = "ipsec end system"
	KeyUsageIpsecTunnel       KeyUsage = "ipsec tunnel"
	KeyUsageIpsecUser         KeyUsage = "ipsec user"
	KeyUsageTimestamping      KeyUsage = "timestamping"
	KeyUsageOcspSigning       KeyUsage = "ocsp signing"
	KeyUsageMicrosoftSgc      KeyUsage = "microsoft sgc"
	KeyUsageNetscapeSgc       KeyUsage = "netscape sgc"
)

type PrivateKeyAlgorithm string

const (
	PrivateKeyAlgorithmRSA     PrivateKeyAlgorithm = "RSA"
	PrivateKeyAlgorithmECDSA   PrivateKeyAlgorithm = "ECDSA"
	PrivateKeyAlgorithmEd25519 PrivateKeyAlgorithm = "Ed25519"
)

type PrivateKeyEncoding string

const (
	PrivateKeyEncodingPkcs1 PrivateKeyEncoding = "PKCS1"
	PrivateKeyEncodingPkcs8 PrivateKeyEncoding = "PKCS8"
)

type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Desired state of the Certificate resource.
	Spec CertificateSpec `json:"spec"`
	// Status of the Certificate. This is set and managed automatically.
	Status CertificateStatus `json:"status"`
}

func (in *Certificate) DeepCopyInto(out *Certificate) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *Certificate) DeepCopy() *Certificate {
	if in == nil {
		return nil
	}
	out := new(Certificate)
	in.DeepCopyInto(out)
	return out
}

func (in *Certificate) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Certificate `json:"items"`
}

func (in *CertificateList) DeepCopyInto(out *CertificateList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Certificate, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *CertificateList) DeepCopy() *CertificateList {
	if in == nil {
		return nil
	}
	out := new(CertificateList)
	in.DeepCopyInto(out)
	return out
}

func (in *CertificateList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type CertificateRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Desired state of the CertificateRequest resource.
	Spec CertificateRequestSpec `json:"spec"`
	// Status of the CertificateRequest. This is set and managed automatically.
	Status CertificateRequestStatus `json:"status"`
}

func (in *CertificateRequest) DeepCopyInto(out *CertificateRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *CertificateRequest) DeepCopy() *CertificateRequest {
	if in == nil {
		return nil
	}
	out := new(CertificateRequest)
	in.DeepCopyInto(out)
	return out
}

func (in *CertificateRequest) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type CertificateRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CertificateRequest `json:"items"`
}

func (in *CertificateRequestList) DeepCopyInto(out *CertificateRequestList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]CertificateRequest, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *CertificateRequestList) DeepCopy() *CertificateRequestList {
	if in == nil {
		return nil
	}
	out := new(CertificateRequestList)
	in.DeepCopyInto(out)
	return out
}

func (in *CertificateRequestList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ClusterIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Desired state of the ClusterIssuer resource.
	Spec IssuerSpec `json:"spec"`
	// Status of the ClusterIssuer. This is set and managed automatically.
	Status IssuerStatus `json:"status"`
}

func (in *ClusterIssuer) DeepCopyInto(out *ClusterIssuer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *ClusterIssuer) DeepCopy() *ClusterIssuer {
	if in == nil {
		return nil
	}
	out := new(ClusterIssuer)
	in.DeepCopyInto(out)
	return out
}

func (in *ClusterIssuer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type ClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterIssuer `json:"items"`
}

func (in *ClusterIssuerList) DeepCopyInto(out *ClusterIssuerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]ClusterIssuer, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *ClusterIssuerList) DeepCopy() *ClusterIssuerList {
	if in == nil {
		return nil
	}
	out := new(ClusterIssuerList)
	in.DeepCopyInto(out)
	return out
}

func (in *ClusterIssuerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Desired state of the Issuer resource.
	Spec IssuerSpec `json:"spec"`
	// Status of the Issuer. This is set and managed automatically.
	Status IssuerStatus `json:"status"`
}

func (in *Issuer) DeepCopyInto(out *Issuer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *Issuer) DeepCopy() *Issuer {
	if in == nil {
		return nil
	}
	out := new(Issuer)
	in.DeepCopyInto(out)
	return out
}

func (in *Issuer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Issuer `json:"items"`
}

func (in *IssuerList) DeepCopyInto(out *IssuerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		l := make([]Issuer, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&l[i])
		}
		out.Items = l
	}
}

func (in *IssuerList) DeepCopy() *IssuerList {
	if in == nil {
		return nil
	}
	out := new(IssuerList)
	in.DeepCopyInto(out)
	return out
}

func (in *IssuerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type CertificateSpec struct {
	// Full X509 name specification (https://golang.org/pkg/crypto/x509/pkix/#Name).
	Subject *X509Subject `json:"subject,omitempty"`
	// CommonName is a common name to be used on the Certificate.
	// The CommonName should have a length of 64 characters or fewer to avoid
	// generating invalid CSRs.
	// This value is ignored by TLS clients when any subject alt name is set.
	// This is x509 behaviour: https://tools.ietf.org/html/rfc6125#section-6.4.4
	CommonName string `json:"commonName,omitempty"`
	// The requested 'duration' (i.e. lifetime) of the Certificate. This option
	// may be ignored/overridden by some issuer types. If unset this defaults to
	// 90 days. Certificate will be renewed either 2/3 through its duration or
	// `renewBefore` period before its expiry, whichever is later. Minimum
	// accepted duration is 1 hour. Value must be in units accepted by Go
	// time.ParseDuration https://golang.org/pkg/time/#ParseDuration
	Duration *metav1.Duration `json:"duration,omitempty"`
	// How long before the currently issued certificate's expiry
	// cert-manager should renew the certificate. The default is 2/3 of the
	// issued certificate's duration. Minimum accepted value is 5 minutes.
	// Value must be in units accepted by Go time.ParseDuration
	// https://golang.org/pkg/time/#ParseDuration
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`
	// DNSNames is a list of DNS subjectAltNames to be set on the Certificate.
	DNSNames []string `json:"dnsNames"`
	// IPAddresses is a list of IP address subjectAltNames to be set on the Certificate.
	IPAddresses []string `json:"ipAddresses"`
	// URIs is a list of URI subjectAltNames to be set on the Certificate.
	URIs []string `json:"uris"`
	// EmailAddresses is a list of email subjectAltNames to be set on the Certificate.
	EmailAddresses []string `json:"emailAddresses"`
	// SecretName is the name of the secret resource that will be automatically
	// created and managed by this Certificate resource.
	// It will be populated with a private key and certificate, signed by the
	// denoted issuer.
	SecretName string `json:"secretName"`
	// SecretTemplate defines annotations and labels to be propagated
	// to the Kubernetes Secret when it is created or updated. Once created,
	// labels and annotations are not yet removed from the Secret when they are
	// removed from the template. See https://github.com/jetstack/cert-manager/issues/4292
	SecretTemplate *CertificateSecretTemplate `json:"secretTemplate,omitempty"`
	// Keystores configures additional keystore output formats stored in the
	// `secretName` Secret resource.
	Keystores *CertificateKeystores `json:"keystores,omitempty"`
	// IssuerRef is a reference to the issuer for this certificate.
	// If the `kind` field is not set, or set to `Issuer`, an Issuer resource
	// with the given name in the same namespace as the Certificate will be used.
	// If the `kind` field is set to `ClusterIssuer`, a ClusterIssuer with the
	// provided name will be used.
	// The `name` field in this stanza is required at all times.
	IssuerRef metav1_1.ObjectReference `json:"issuerRef"`
	// IsCA will mark this Certificate as valid for certificate signing.
	// This will automatically add the `cert sign` usage to the list of `usages`.
	IsCA bool `json:"isCA,omitempty"`
	// Usages is the set of x509 usages that are requested for the certificate.
	// Defaults to `digital signature` and `key encipherment` if not specified.
	Usages []KeyUsage `json:"usages"`
	// Options to control private keys used for the Certificate.
	PrivateKey *CertificatePrivateKey `json:"privateKey,omitempty"`
	// EncodeUsagesInRequest controls whether key usages should be present
	// in the CertificateRequest
	EncodeUsagesInRequest bool `json:"encodeUsagesInRequest,omitempty"`
	// revisionHistoryLimit is the maximum number of CertificateRequest revisions
	// that are maintained in the Certificate's history. Each revision represents
	// a single `CertificateRequest` created by this Certificate, either when it
	// was created, renewed, or Spec was changed. Revisions will be removed by
	// oldest first if the number of revisions exceeds this number. If set,
	// revisionHistoryLimit must be a value of `1` or greater. If unset (`nil`),
	// revisions will not be garbage collected. Default value is `nil`.
	RevisionHistoryLimit int `json:"revisionHistoryLimit,omitempty"`
}

func (in *CertificateSpec) DeepCopyInto(out *CertificateSpec) {
	*out = *in
	if in.Subject != nil {
		in, out := &in.Subject, &out.Subject
		*out = new(X509Subject)
		(*in).DeepCopyInto(*out)
	}
	if in.Duration != nil {
		in, out := &in.Duration, &out.Duration
		*out = new(metav1.Duration)
		(*in).DeepCopyInto(*out)
	}
	if in.RenewBefore != nil {
		in, out := &in.RenewBefore, &out.RenewBefore
		*out = new(metav1.Duration)
		(*in).DeepCopyInto(*out)
	}
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
	if in.URIs != nil {
		t := make([]string, len(in.URIs))
		copy(t, in.URIs)
		out.URIs = t
	}
	if in.EmailAddresses != nil {
		t := make([]string, len(in.EmailAddresses))
		copy(t, in.EmailAddresses)
		out.EmailAddresses = t
	}
	if in.SecretTemplate != nil {
		in, out := &in.SecretTemplate, &out.SecretTemplate
		*out = new(CertificateSecretTemplate)
		(*in).DeepCopyInto(*out)
	}
	if in.Keystores != nil {
		in, out := &in.Keystores, &out.Keystores
		*out = new(CertificateKeystores)
		(*in).DeepCopyInto(*out)
	}
	in.IssuerRef.DeepCopyInto(&out.IssuerRef)
	if in.Usages != nil {
		t := make([]KeyUsage, len(in.Usages))
		copy(t, in.Usages)
		out.Usages = t
	}
	if in.PrivateKey != nil {
		in, out := &in.PrivateKey, &out.PrivateKey
		*out = new(CertificatePrivateKey)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CertificateSpec) DeepCopy() *CertificateSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateSpec)
	in.DeepCopyInto(out)
	return out
}

type CertificateStatus struct {
	// List of status conditions to indicate the status of certificates.
	// Known condition types are `Ready` and `Issuing`.
	Conditions []CertificateCondition `json:"conditions"`
	// LastFailureTime is the time as recorded by the Certificate controller
	// of the most recent failure to complete a CertificateRequest for this
	// Certificate resource.
	// If set, cert-manager will not re-request another Certificate until
	// 1 hour has elapsed from this time.
	LastFailureTime *metav1.Time `json:"lastFailureTime,omitempty"`
	// The time after which the certificate stored in the secret named
	// by this resource in spec.secretName is valid.
	NotBefore *metav1.Time `json:"notBefore,omitempty"`
	// The expiration time of the certificate stored in the secret named
	// by this resource in `spec.secretName`.
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
	// RenewalTime is the time at which the certificate will be next
	// renewed.
	// If not set, no upcoming renewal is scheduled.
	RenewalTime *metav1.Time `json:"renewalTime,omitempty"`
	// The current 'revision' of the certificate as issued.
	// When a CertificateRequest resource is created, it will have the
	// `cert-manager.io/certificate-revision` set to one greater than the
	// current value of this field.
	// Upon issuance, this field will be set to the value of the annotation
	// on the CertificateRequest resource used to issue the certificate.
	// Persisting the value on the CertificateRequest resource allows the
	// certificates controller to know whether a request is part of an old
	// issuance or if it is part of the ongoing revision's issuance by
	// checking if the revision value in the annotation is greater than this
	// field.
	Revision int `json:"revision,omitempty"`
	// The name of the Secret resource containing the private key to be used
	// for the next certificate iteration.
	// The keymanager controller will automatically set this field if the
	// `Issuing` condition is set to `True`.
	// It will automatically unset this field when the Issuing condition is
	// not set or False.
	NextPrivateKeySecretName string `json:"nextPrivateKeySecretName,omitempty"`
}

func (in *CertificateStatus) DeepCopyInto(out *CertificateStatus) {
	*out = *in
	if in.Conditions != nil {
		l := make([]CertificateCondition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&l[i])
		}
		out.Conditions = l
	}
	if in.LastFailureTime != nil {
		in, out := &in.LastFailureTime, &out.LastFailureTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
	if in.NotBefore != nil {
		in, out := &in.NotBefore, &out.NotBefore
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
	if in.NotAfter != nil {
		in, out := &in.NotAfter, &out.NotAfter
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
	if in.RenewalTime != nil {
		in, out := &in.RenewalTime, &out.RenewalTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CertificateStatus) DeepCopy() *CertificateStatus {
	if in == nil {
		return nil
	}
	out := new(CertificateStatus)
	in.DeepCopyInto(out)
	return out
}

type CertificateRequestSpec struct {
	// The requested 'duration' (i.e. lifetime) of the Certificate.
	// This option may be ignored/overridden by some issuer types.
	Duration *metav1.Duration `json:"duration,omitempty"`
	// IssuerRef is a reference to the issuer for this CertificateRequest.  If
	// the `kind` field is not set, or set to `Issuer`, an Issuer resource with
	// the given name in the same namespace as the CertificateRequest will be
	// used.  If the `kind` field is set to `ClusterIssuer`, a ClusterIssuer with
	// the provided name will be used. The `name` field in this stanza is
	// required at all times. The group field refers to the API group of the
	// issuer which defaults to `cert-manager.io` if empty.
	IssuerRef metav1_1.ObjectReference `json:"issuerRef"`
	// The PEM-encoded x509 certificate signing request to be submitted to the
	// CA for signing.
	Request []byte `json:"request,omitempty"`
	// IsCA will request to mark the certificate as valid for certificate signing
	// when submitting to the issuer.
	// This will automatically add the `cert sign` usage to the list of `usages`.
	IsCA bool `json:"isCA,omitempty"`
	// Usages is the set of x509 usages that are requested for the certificate.
	// If usages are set they SHOULD be encoded inside the CSR spec
	// Defaults to `digital signature` and `key encipherment` if not specified.
	Usages []KeyUsage `json:"usages"`
	// Username contains the name of the user that created the CertificateRequest.
	// Populated by the cert-manager webhook on creation and immutable.
	Username string `json:"username,omitempty"`
	// UID contains the uid of the user that created the CertificateRequest.
	// Populated by the cert-manager webhook on creation and immutable.
	UID string `json:"uid,omitempty"`
	// Groups contains group membership of the user that created the CertificateRequest.
	// Populated by the cert-manager webhook on creation and immutable.
	Groups []string `json:"groups"`
}

func (in *CertificateRequestSpec) DeepCopyInto(out *CertificateRequestSpec) {
	*out = *in
	if in.Duration != nil {
		in, out := &in.Duration, &out.Duration
		*out = new(metav1.Duration)
		(*in).DeepCopyInto(*out)
	}
	in.IssuerRef.DeepCopyInto(&out.IssuerRef)
	if in.Usages != nil {
		t := make([]KeyUsage, len(in.Usages))
		copy(t, in.Usages)
		out.Usages = t
	}
	if in.Groups != nil {
		t := make([]string, len(in.Groups))
		copy(t, in.Groups)
		out.Groups = t
	}
}

func (in *CertificateRequestSpec) DeepCopy() *CertificateRequestSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateRequestSpec)
	in.DeepCopyInto(out)
	return out
}

type CertificateRequestStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready` and `InvalidRequest`.
	Conditions []CertificateRequestCondition `json:"conditions"`
	// The PEM encoded x509 certificate resulting from the certificate
	// signing request.
	// If not set, the CertificateRequest has either not been completed or has
	// failed. More information on failure can be found by checking the
	// `conditions` field.
	Certificate []byte `json:"certificate,omitempty"`
	// The PEM encoded x509 certificate of the signer, also known as the CA
	// (Certificate Authority).
	// This is set on a best-effort basis by different issuers.
	// If not set, the CA is assumed to be unknown/not available.
	CA []byte `json:"ca,omitempty"`
	// FailureTime stores the time that this CertificateRequest failed. This is
	// used to influence garbage collection and back-off.
	FailureTime *metav1.Time `json:"failureTime,omitempty"`
}

func (in *CertificateRequestStatus) DeepCopyInto(out *CertificateRequestStatus) {
	*out = *in
	if in.Conditions != nil {
		l := make([]CertificateRequestCondition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&l[i])
		}
		out.Conditions = l
	}
	if in.FailureTime != nil {
		in, out := &in.FailureTime, &out.FailureTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CertificateRequestStatus) DeepCopy() *CertificateRequestStatus {
	if in == nil {
		return nil
	}
	out := new(CertificateRequestStatus)
	in.DeepCopyInto(out)
	return out
}

type IssuerSpec struct {
	IssuerConfig `json:",inline"`
}

func (in *IssuerSpec) DeepCopyInto(out *IssuerSpec) {
	*out = *in
	out.IssuerConfig = in.IssuerConfig
}

func (in *IssuerSpec) DeepCopy() *IssuerSpec {
	if in == nil {
		return nil
	}
	out := new(IssuerSpec)
	in.DeepCopyInto(out)
	return out
}

type IssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	Conditions []IssuerCondition `json:"conditions"`
	// ACME specific status options.
	// This field should only be set if the Issuer is configured to use an ACME
	// server to issue certificates.
	ACME *acmev1.ACMEIssuerStatus `json:"acme,omitempty"`
}

func (in *IssuerStatus) DeepCopyInto(out *IssuerStatus) {
	*out = *in
	if in.Conditions != nil {
		l := make([]IssuerCondition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&l[i])
		}
		out.Conditions = l
	}
	if in.ACME != nil {
		in, out := &in.ACME, &out.ACME
		*out = new(acmev1.ACMEIssuerStatus)
		(*in).DeepCopyInto(*out)
	}
}

func (in *IssuerStatus) DeepCopy() *IssuerStatus {
	if in == nil {
		return nil
	}
	out := new(IssuerStatus)
	in.DeepCopyInto(out)
	return out
}

type X509Subject struct {
	// Organizations to be used on the Certificate.
	Organizations []string `json:"organizations"`
	// Countries to be used on the Certificate.
	Countries []string `json:"countries"`
	// Organizational Units to be used on the Certificate.
	OrganizationalUnits []string `json:"organizationalUnits"`
	// Cities to be used on the Certificate.
	Localities []string `json:"localities"`
	// State/Provinces to be used on the Certificate.
	Provinces []string `json:"provinces"`
	// Street addresses to be used on the Certificate.
	StreetAddresses []string `json:"streetAddresses"`
	// Postal codes to be used on the Certificate.
	PostalCodes []string `json:"postalCodes"`
	// Serial number to be used on the Certificate.
	SerialNumber string `json:"serialNumber,omitempty"`
}

func (in *X509Subject) DeepCopyInto(out *X509Subject) {
	*out = *in
	if in.Organizations != nil {
		t := make([]string, len(in.Organizations))
		copy(t, in.Organizations)
		out.Organizations = t
	}
	if in.Countries != nil {
		t := make([]string, len(in.Countries))
		copy(t, in.Countries)
		out.Countries = t
	}
	if in.OrganizationalUnits != nil {
		t := make([]string, len(in.OrganizationalUnits))
		copy(t, in.OrganizationalUnits)
		out.OrganizationalUnits = t
	}
	if in.Localities != nil {
		t := make([]string, len(in.Localities))
		copy(t, in.Localities)
		out.Localities = t
	}
	if in.Provinces != nil {
		t := make([]string, len(in.Provinces))
		copy(t, in.Provinces)
		out.Provinces = t
	}
	if in.StreetAddresses != nil {
		t := make([]string, len(in.StreetAddresses))
		copy(t, in.StreetAddresses)
		out.StreetAddresses = t
	}
	if in.PostalCodes != nil {
		t := make([]string, len(in.PostalCodes))
		copy(t, in.PostalCodes)
		out.PostalCodes = t
	}
}

func (in *X509Subject) DeepCopy() *X509Subject {
	if in == nil {
		return nil
	}
	out := new(X509Subject)
	in.DeepCopyInto(out)
	return out
}

type CertificateSecretTemplate struct {
	// Annotations is a key value map to be copied to the target Kubernetes Secret.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Labels is a key value map to be copied to the target Kubernetes Secret.
	Labels map[string]string `json:"labels,omitempty"`
}

func (in *CertificateSecretTemplate) DeepCopyInto(out *CertificateSecretTemplate) {
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

func (in *CertificateSecretTemplate) DeepCopy() *CertificateSecretTemplate {
	if in == nil {
		return nil
	}
	out := new(CertificateSecretTemplate)
	in.DeepCopyInto(out)
	return out
}

type CertificateKeystores struct {
	// JKS configures options for storing a JKS keystore in the
	// `spec.secretName` Secret resource.
	JKS *JKSKeystore `json:"jks,omitempty"`
	// Pkcs12 configures options for storing a PKCS12 keystore in the
	// `spec.secretName` Secret resource.
	PKCS12 *PKCS12Keystore `json:"pkcs12,omitempty"`
}

func (in *CertificateKeystores) DeepCopyInto(out *CertificateKeystores) {
	*out = *in
	if in.JKS != nil {
		in, out := &in.JKS, &out.JKS
		*out = new(JKSKeystore)
		(*in).DeepCopyInto(*out)
	}
	if in.PKCS12 != nil {
		in, out := &in.PKCS12, &out.PKCS12
		*out = new(PKCS12Keystore)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CertificateKeystores) DeepCopy() *CertificateKeystores {
	if in == nil {
		return nil
	}
	out := new(CertificateKeystores)
	in.DeepCopyInto(out)
	return out
}

type CertificatePrivateKey struct {
	// RotationPolicy controls how private keys should be regenerated when a
	// re-issuance is being processed.
	// If set to Never, a private key will only be generated if one does not
	// already exist in the target `spec.secretName`. If one does exists but it
	// does not have the correct algorithm or size, a warning will be raised
	// to await user intervention.
	// If set to Always, a private key matching the specified requirements
	// will be generated whenever a re-issuance occurs.
	// Default is 'Never' for backward compatibility.
	RotationPolicy string `json:"rotationPolicy"`
	// The private key cryptography standards (PKCS) encoding for this
	// certificate's private key to be encoded in.
	// If provided, allowed values are `PKCS1` and `PKCS8` standing for PKCS#1
	// and PKCS#8, respectively.
	// Defaults to `PKCS1` if not specified.
	Encoding PrivateKeyEncoding `json:"encoding,omitempty"`
	// Algorithm is the private key algorithm of the corresponding private key
	// for this certificate. If provided, allowed values are either `RSA`,`Ed25519` or `ECDSA`
	// If `algorithm` is specified and `size` is not provided,
	// key size of 256 will be used for `ECDSA` key algorithm and
	// key size of 2048 will be used for `RSA` key algorithm.
	// key size is ignored when using the `Ed25519` key algorithm.
	Algorithm PrivateKeyAlgorithm `json:"algorithm,omitempty"`
	// Size is the key bit size of the corresponding private key for this certificate.
	// If `algorithm` is set to `RSA`, valid values are `2048`, `4096` or `8192`,
	// and will default to `2048` if not specified.
	// If `algorithm` is set to `ECDSA`, valid values are `256`, `384` or `521`,
	// and will default to `256` if not specified.
	// If `algorithm` is set to `Ed25519`, Size is ignored.
	// No other values are allowed.
	Size int `json:"size,omitempty"`
}

func (in *CertificatePrivateKey) DeepCopyInto(out *CertificatePrivateKey) {
	*out = *in
}

func (in *CertificatePrivateKey) DeepCopy() *CertificatePrivateKey {
	if in == nil {
		return nil
	}
	out := new(CertificatePrivateKey)
	in.DeepCopyInto(out)
	return out
}

type CertificateCondition struct {
	// Type of the condition, known values are (`Ready`, `Issuing`).
	Type CertificateConditionType `json:"type"`
	// Status of the condition, one of (`True`, `False`, `Unknown`).
	Status metav1.ConditionStatus `json:"status"`
	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string `json:"reason,omitempty"`
	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string `json:"message,omitempty"`
	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Certificate.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

func (in *CertificateCondition) DeepCopyInto(out *CertificateCondition) {
	*out = *in
	if in.LastTransitionTime != nil {
		in, out := &in.LastTransitionTime, &out.LastTransitionTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CertificateCondition) DeepCopy() *CertificateCondition {
	if in == nil {
		return nil
	}
	out := new(CertificateCondition)
	in.DeepCopyInto(out)
	return out
}

type CertificateRequestCondition struct {
	// Type of the condition, known values are (`Ready`, `InvalidRequest`,
	// `Approved`, `Denied`).
	Type CertificateRequestConditionType `json:"type"`
	// Status of the condition, one of (`True`, `False`, `Unknown`).
	Status metav1.ConditionStatus `json:"status"`
	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string `json:"reason,omitempty"`
	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string `json:"message,omitempty"`
}

func (in *CertificateRequestCondition) DeepCopyInto(out *CertificateRequestCondition) {
	*out = *in
	if in.LastTransitionTime != nil {
		in, out := &in.LastTransitionTime, &out.LastTransitionTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *CertificateRequestCondition) DeepCopy() *CertificateRequestCondition {
	if in == nil {
		return nil
	}
	out := new(CertificateRequestCondition)
	in.DeepCopyInto(out)
	return out
}

type IssuerConfig struct {
	// ACME configures this issuer to communicate with a RFC8555 (ACME) server
	// to obtain signed x509 certificates.
	ACME *acmev1.ACMEIssuer `json:"acme,omitempty"`
	// CA configures this issuer to sign certificates using a signing CA keypair
	// stored in a Secret resource.
	// This is used to build internal PKIs that are managed by cert-manager.
	CA *CAIssuer `json:"ca,omitempty"`
	// Vault configures this issuer to sign certificates using a HashiCorp Vault
	// PKI backend.
	Vault *VaultIssuer `json:"vault,omitempty"`
	// SelfSigned configures this issuer to 'self sign' certificates using the
	// private key used to create the CertificateRequest object.
	SelfSigned *SelfSignedIssuer `json:"selfSigned,omitempty"`
	// Venafi configures this issuer to sign certificates using a Venafi TPP
	// or Venafi Cloud policy zone.
	Venafi *VenafiIssuer `json:"venafi,omitempty"`
}

func (in *IssuerConfig) DeepCopyInto(out *IssuerConfig) {
	*out = *in
	if in.ACME != nil {
		in, out := &in.ACME, &out.ACME
		*out = new(acmev1.ACMEIssuer)
		(*in).DeepCopyInto(*out)
	}
	if in.CA != nil {
		in, out := &in.CA, &out.CA
		*out = new(CAIssuer)
		(*in).DeepCopyInto(*out)
	}
	if in.Vault != nil {
		in, out := &in.Vault, &out.Vault
		*out = new(VaultIssuer)
		(*in).DeepCopyInto(*out)
	}
	if in.SelfSigned != nil {
		in, out := &in.SelfSigned, &out.SelfSigned
		*out = new(SelfSignedIssuer)
		(*in).DeepCopyInto(*out)
	}
	if in.Venafi != nil {
		in, out := &in.Venafi, &out.Venafi
		*out = new(VenafiIssuer)
		(*in).DeepCopyInto(*out)
	}
}

func (in *IssuerConfig) DeepCopy() *IssuerConfig {
	if in == nil {
		return nil
	}
	out := new(IssuerConfig)
	in.DeepCopyInto(out)
	return out
}

type IssuerCondition struct {
	// Type of the condition, known values are (`Ready`).
	Type IssuerConditionType `json:"type"`
	// Status of the condition, one of (`True`, `False`, `Unknown`).
	Status metav1.ConditionStatus `json:"status"`
	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	Reason string `json:"reason,omitempty"`
	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	Message string `json:"message,omitempty"`
	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Issuer.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

func (in *IssuerCondition) DeepCopyInto(out *IssuerCondition) {
	*out = *in
	if in.LastTransitionTime != nil {
		in, out := &in.LastTransitionTime, &out.LastTransitionTime
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

func (in *IssuerCondition) DeepCopy() *IssuerCondition {
	if in == nil {
		return nil
	}
	out := new(IssuerCondition)
	in.DeepCopyInto(out)
	return out
}

type JKSKeystore struct {
	// Create enables JKS keystore creation for the Certificate.
	// If true, a file named `keystore.jks` will be created in the target
	// Secret resource, encrypted using the password stored in
	// `passwordSecretRef`.
	// The keystore file will only be updated upon re-issuance.
	// A file named `truststore.jks` will also be created in the target
	// Secret resource, encrypted using the password stored in
	// `passwordSecretRef` containing the issuing Certificate Authority
	Create bool `json:"create"`
	// PasswordSecretRef is a reference to a key in a Secret resource
	// containing the password used to encrypt the JKS keystore.
	PasswordSecretRef metav1_1.SecretKeySelector `json:"passwordSecretRef"`
}

func (in *JKSKeystore) DeepCopyInto(out *JKSKeystore) {
	*out = *in
	in.PasswordSecretRef.DeepCopyInto(&out.PasswordSecretRef)
}

func (in *JKSKeystore) DeepCopy() *JKSKeystore {
	if in == nil {
		return nil
	}
	out := new(JKSKeystore)
	in.DeepCopyInto(out)
	return out
}

type PKCS12Keystore struct {
	// Create enables PKCS12 keystore creation for the Certificate.
	// If true, a file named `keystore.p12` will be created in the target
	// Secret resource, encrypted using the password stored in
	// `passwordSecretRef`.
	// The keystore file will only be updated upon re-issuance.
	// A file named `truststore.p12` will also be created in the target
	// Secret resource, encrypted using the password stored in
	// `passwordSecretRef` containing the issuing Certificate Authority
	Create bool `json:"create"`
	// PasswordSecretRef is a reference to a key in a Secret resource
	// containing the password used to encrypt the PKCS12 keystore.
	PasswordSecretRef metav1_1.SecretKeySelector `json:"passwordSecretRef"`
}

func (in *PKCS12Keystore) DeepCopyInto(out *PKCS12Keystore) {
	*out = *in
	in.PasswordSecretRef.DeepCopyInto(&out.PasswordSecretRef)
}

func (in *PKCS12Keystore) DeepCopy() *PKCS12Keystore {
	if in == nil {
		return nil
	}
	out := new(PKCS12Keystore)
	in.DeepCopyInto(out)
	return out
}

type CAIssuer struct {
	// SecretName is the name of the secret used to sign Certificates issued
	// by this Issuer.
	SecretName string `json:"secretName"`
	// The CRL distribution points is an X.509 v3 certificate extension which identifies
	// the location of the CRL from which the revocation of this certificate can be checked.
	// If not set, certificates will be issued without distribution points set.
	CRLDistributionPoints []string `json:"crlDistributionPoints"`
	// The OCSP server list is an X.509 v3 extension that defines a list of
	// URLs of OCSP responders. The OCSP responders can be queried for the
	// revocation status of an issued certificate. If not set, the
	// certificate will be issued with no OCSP servers set. For example, an
	// OCSP server URL could be "http://ocsp.int-x3.letsencrypt.org".
	OCSPServers []string `json:"ocspServers"`
}

func (in *CAIssuer) DeepCopyInto(out *CAIssuer) {
	*out = *in
	if in.CRLDistributionPoints != nil {
		t := make([]string, len(in.CRLDistributionPoints))
		copy(t, in.CRLDistributionPoints)
		out.CRLDistributionPoints = t
	}
	if in.OCSPServers != nil {
		t := make([]string, len(in.OCSPServers))
		copy(t, in.OCSPServers)
		out.OCSPServers = t
	}
}

func (in *CAIssuer) DeepCopy() *CAIssuer {
	if in == nil {
		return nil
	}
	out := new(CAIssuer)
	in.DeepCopyInto(out)
	return out
}

type VaultIssuer struct {
	// Auth configures how cert-manager authenticates with the Vault server.
	Auth VaultAuth `json:"auth"`
	// Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".
	Server string `json:"server"`
	// Path is the mount path of the Vault PKI backend's `sign` endpoint, e.g:
	// "my_pki_mount/sign/my-role-name".
	Path string `json:"path"`
	// Name of the vault namespace. Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1"
	// More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces
	Namespace string `json:"namespace,omitempty"`
	// PEM-encoded CA bundle (base64-encoded) used to validate Vault server
	// certificate. Only used if the Server URL is using HTTPS protocol. This
	// parameter is ignored for plain HTTP protocol connection. If not set the
	// system root certificates are used to validate the TLS connection.
	CABundle []byte `json:"caBundle,omitempty"`
}

func (in *VaultIssuer) DeepCopyInto(out *VaultIssuer) {
	*out = *in
	in.Auth.DeepCopyInto(&out.Auth)
}

func (in *VaultIssuer) DeepCopy() *VaultIssuer {
	if in == nil {
		return nil
	}
	out := new(VaultIssuer)
	in.DeepCopyInto(out)
	return out
}

type SelfSignedIssuer struct {
	// The CRL distribution points is an X.509 v3 certificate extension which identifies
	// the location of the CRL from which the revocation of this certificate can be checked.
	// If not set certificate will be issued without CDP. Values are strings.
	CRLDistributionPoints []string `json:"crlDistributionPoints"`
}

func (in *SelfSignedIssuer) DeepCopyInto(out *SelfSignedIssuer) {
	*out = *in
	if in.CRLDistributionPoints != nil {
		t := make([]string, len(in.CRLDistributionPoints))
		copy(t, in.CRLDistributionPoints)
		out.CRLDistributionPoints = t
	}
}

func (in *SelfSignedIssuer) DeepCopy() *SelfSignedIssuer {
	if in == nil {
		return nil
	}
	out := new(SelfSignedIssuer)
	in.DeepCopyInto(out)
	return out
}

type VenafiIssuer struct {
	// Zone is the Venafi Policy Zone to use for this issuer.
	// All requests made to the Venafi platform will be restricted by the named
	// zone policy.
	// This field is required.
	Zone string `json:"zone"`
	// TPP specifies Trust Protection Platform configuration settings.
	// Only one of TPP or Cloud may be specified.
	TPP *VenafiTPP `json:"tpp,omitempty"`
	// Cloud specifies the Venafi cloud configuration settings.
	// Only one of TPP or Cloud may be specified.
	Cloud *VenafiCloud `json:"cloud,omitempty"`
}

func (in *VenafiIssuer) DeepCopyInto(out *VenafiIssuer) {
	*out = *in
	if in.TPP != nil {
		in, out := &in.TPP, &out.TPP
		*out = new(VenafiTPP)
		(*in).DeepCopyInto(*out)
	}
	if in.Cloud != nil {
		in, out := &in.Cloud, &out.Cloud
		*out = new(VenafiCloud)
		(*in).DeepCopyInto(*out)
	}
}

func (in *VenafiIssuer) DeepCopy() *VenafiIssuer {
	if in == nil {
		return nil
	}
	out := new(VenafiIssuer)
	in.DeepCopyInto(out)
	return out
}

type VaultAuth struct {
	// TokenSecretRef authenticates with Vault by presenting a token.
	TokenSecretRef *metav1_1.SecretKeySelector `json:"tokenSecretRef,omitempty"`
	// AppRole authenticates with Vault using the App Role auth mechanism,
	// with the role and secret stored in a Kubernetes Secret resource.
	AppRole *VaultAppRole `json:"appRole,omitempty"`
	// Kubernetes authenticates with Vault by passing the ServiceAccount
	// token stored in the named Secret resource to the Vault server.
	Kubernetes *VaultKubernetesAuth `json:"kubernetes,omitempty"`
}

func (in *VaultAuth) DeepCopyInto(out *VaultAuth) {
	*out = *in
	if in.TokenSecretRef != nil {
		in, out := &in.TokenSecretRef, &out.TokenSecretRef
		*out = new(metav1_1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
	if in.AppRole != nil {
		in, out := &in.AppRole, &out.AppRole
		*out = new(VaultAppRole)
		(*in).DeepCopyInto(*out)
	}
	if in.Kubernetes != nil {
		in, out := &in.Kubernetes, &out.Kubernetes
		*out = new(VaultKubernetesAuth)
		(*in).DeepCopyInto(*out)
	}
}

func (in *VaultAuth) DeepCopy() *VaultAuth {
	if in == nil {
		return nil
	}
	out := new(VaultAuth)
	in.DeepCopyInto(out)
	return out
}

type VenafiTPP struct {
	// URL is the base URL for the vedsdk endpoint of the Venafi TPP instance,
	// for example: "https://tpp.example.com/vedsdk".
	URL string `json:"url"`
	// CredentialsRef is a reference to a Secret containing the username and
	// password for the TPP server.
	// The secret must contain two keys, 'username' and 'password'.
	CredentialsRef metav1_1.LocalObjectReference `json:"credentialsRef"`
	// CABundle is a PEM encoded TLS certificate to use to verify connections to
	// the TPP instance.
	// If specified, system roots will not be used and the issuing CA for the
	// TPP instance must be verifiable using the provided root.
	// If not specified, the connection will be verified using the cert-manager
	// system root certificates.
	CABundle []byte `json:"caBundle,omitempty"`
}

func (in *VenafiTPP) DeepCopyInto(out *VenafiTPP) {
	*out = *in
	in.CredentialsRef.DeepCopyInto(&out.CredentialsRef)
}

func (in *VenafiTPP) DeepCopy() *VenafiTPP {
	if in == nil {
		return nil
	}
	out := new(VenafiTPP)
	in.DeepCopyInto(out)
	return out
}

type VenafiCloud struct {
	// URL is the base URL for Venafi Cloud.
	// Defaults to "https://api.venafi.cloud/v1".
	URL string `json:"url,omitempty"`
	// APITokenSecretRef is a secret key selector for the Venafi Cloud API token.
	APITokenSecretRef metav1_1.SecretKeySelector `json:"apiTokenSecretRef"`
}

func (in *VenafiCloud) DeepCopyInto(out *VenafiCloud) {
	*out = *in
	in.APITokenSecretRef.DeepCopyInto(&out.APITokenSecretRef)
}

func (in *VenafiCloud) DeepCopy() *VenafiCloud {
	if in == nil {
		return nil
	}
	out := new(VenafiCloud)
	in.DeepCopyInto(out)
	return out
}

type VaultAppRole struct {
	// Path where the App Role authentication backend is mounted in Vault, e.g:
	// "approle"
	Path string `json:"path"`
	// RoleID configured in the App Role authentication backend when setting
	// up the authentication backend in Vault.
	RoleId string `json:"roleId"`
	// Reference to a key in a Secret that contains the App Role secret used
	// to authenticate with Vault.
	// The `key` field must be specified and denotes which entry within the Secret
	// resource is used as the app role secret.
	SecretRef metav1_1.SecretKeySelector `json:"secretRef"`
}

func (in *VaultAppRole) DeepCopyInto(out *VaultAppRole) {
	*out = *in
	in.SecretRef.DeepCopyInto(&out.SecretRef)
}

func (in *VaultAppRole) DeepCopy() *VaultAppRole {
	if in == nil {
		return nil
	}
	out := new(VaultAppRole)
	in.DeepCopyInto(out)
	return out
}

type VaultKubernetesAuth struct {
	// The Vault mountPath here is the mount path to use when authenticating with
	// Vault. For example, setting a value to `/v1/auth/foo`, will use the path
	// `/v1/auth/foo/login` to authenticate with Vault. If unspecified, the
	// default value "/v1/auth/kubernetes" will be used.
	Path string `json:"mountPath,omitempty"`
	// The required Secret field containing a Kubernetes ServiceAccount JWT used
	// for authenticating with Vault. Use of 'ambient credentials' is not
	// supported.
	SecretRef metav1_1.SecretKeySelector `json:"secretRef"`
	// A required field containing the Vault Role to assume. A Role binds a
	// Kubernetes ServiceAccount with a set of Vault policies.
	Role string `json:"role"`
}

func (in *VaultKubernetesAuth) DeepCopyInto(out *VaultKubernetesAuth) {
	*out = *in
	in.SecretRef.DeepCopyInto(&out.SecretRef)
}

func (in *VaultKubernetesAuth) DeepCopy() *VaultKubernetesAuth {
	if in == nil {
		return nil
	}
	out := new(VaultKubernetesAuth)
	in.DeepCopyInto(out)
	return out
}
