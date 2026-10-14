package e2eutil

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"

	"go.f110.dev/xerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/k8s"
)

// NamespacedOperator is the operator that watches only Namespace.
// It shares the CustomResourceDefinitions and their conversion webhook with the operator that is deployed in advance.
type NamespacedOperator struct {
	Namespace string

	objects k8s.Objects
}

// DeployNamespacedOperator deploys the operator of the all-in-one manifest to namespace and waits until its webhook becomes reachable.
func DeployNamespacedOperator(ctx context.Context, cfg *rest.Config, manifestFile, namespace string) (*NamespacedOperator, error) {
	manifest, err := os.ReadFile(manifestFile)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	caCert, caKey, err := cert.CreateCertificateAuthority("heimdallr-operator e2e CA", "", "", "", "ecdsa")
	if err != nil {
		return nil, err
	}
	objs, err := NamespacedOperatorManifest(manifest, namespace, caCert, caKey)
	if err != nil {
		return nil, err
	}

	op := &NamespacedOperator{Namespace: namespace, objects: objs}
	if err := objs.Apply(cfg, "e2e"); err != nil {
		return op, err
	}
	if err := WaitForWebhookReachable(ctx, cfg, namespace); err != nil {
		return op, err
	}

	return op, nil
}

// Delete deletes the namespace and the cluster-scoped objects of the operator.
func (o *NamespacedOperator) Delete(ctx context.Context, cfg *rest.Config) error {
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return xerrors.WithStack(err)
	}

	for _, v := range o.objects {
		if v.GetNamespace() != "" {
			continue
		}

		switch v.GetKind() {
		case "Namespace":
			err = c.CoreV1().Namespaces().Delete(ctx, v.GetName(), metav1.DeleteOptions{})
		case "ClusterRole":
			err = c.RbacV1().ClusterRoles().Delete(ctx, v.GetName(), metav1.DeleteOptions{})
		case "ClusterRoleBinding":
			err = c.RbacV1().ClusterRoleBindings().Delete(ctx, v.GetName(), metav1.DeleteOptions{})
		case "ValidatingWebhookConfiguration":
			err = c.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, v.GetName(), metav1.DeleteOptions{})
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

// NamespacedOperatorManifest converts the all-in-one manifest into the manifest of the operator that watches only namespace.
// The CustomResourceDefinitions are dropped because they are shared by all operators in the cluster.
// The names of the cluster-scoped objects get namespace as the suffix to avoid conflicting with other operators.
// The certificate of the webhook server is issued by caCert.
func NamespacedOperatorManifest(manifest []byte, namespace string, caCert *x509.Certificate, caKey crypto.PrivateKey) (k8s.Objects, error) {
	objs, err := k8s.LoadUnstructuredFromString(manifest)
	if err != nil {
		return nil, err
	}

	var dnsNames []string
	for _, obj := range objs {
		if obj.GetKind() != "ValidatingWebhookConfiguration" {
			continue
		}
		webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
		if err != nil {
			return nil, xerrors.WithStack(err)
		}
		for _, v := range webhooks {
			name, _, err := unstructured.NestedString(v.(map[string]any), "clientConfig", "service", "name")
			if err != nil {
				return nil, xerrors.WithStack(err)
			}
			dnsNames = append(dnsNames, fmt.Sprintf("%s.%s.svc", name, namespace))
		}
	}
	if len(dnsNames) == 0 {
		return nil, xerrors.New("the manifest doesn't have the webhook")
	}
	serverCert, serverKey, err := webhookServerCertificate(caCert, caKey, dnsNames)
	if err != nil {
		return nil, err
	}
	caBundle := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))

	ns := &unstructured.Unstructured{}
	ns.SetAPIVersion("v1")
	ns.SetKind("Namespace")
	ns.SetName(namespace)
	converted := k8s.Objects{ns}
	var injectedCert, addedArg bool
	for _, obj := range objs {
		switch obj.GetKind() {
		case "CustomResourceDefinition", "Namespace":
			continue
		case "ClusterRole":
			obj.SetName(clusterScopedName(obj.GetName(), namespace))
		case "ClusterRoleBinding":
			obj.SetName(clusterScopedName(obj.GetName(), namespace))
			roleRef, _, err := unstructured.NestedString(obj.Object, "roleRef", "name")
			if err != nil {
				return nil, xerrors.WithStack(err)
			}
			if err := unstructured.SetNestedField(obj.Object, clusterScopedName(roleRef, namespace), "roleRef", "name"); err != nil {
				return nil, xerrors.WithStack(err)
			}
			if err := setSubjectsNamespace(obj, namespace); err != nil {
				return nil, err
			}
		case "ValidatingWebhookConfiguration":
			obj.SetName(clusterScopedName(obj.GetName(), namespace))
			if err := limitWebhooksToNamespace(obj, namespace, caBundle); err != nil {
				return nil, err
			}
		case "RoleBinding":
			obj.SetNamespace(namespace)
			if err := setSubjectsNamespace(obj, namespace); err != nil {
				return nil, err
			}
		case "Secret":
			obj.SetNamespace(namespace)
			if _, ok, _ := unstructured.NestedString(obj.Object, "stringData", "webhook.crt"); ok {
				if err := unstructured.SetNestedField(obj.Object, string(serverCert), "stringData", "webhook.crt"); err != nil {
					return nil, xerrors.WithStack(err)
				}
				if err := unstructured.SetNestedField(obj.Object, string(serverKey), "stringData", "webhook.key"); err != nil {
					return nil, xerrors.WithStack(err)
				}
				injectedCert = true
			}
		case "Deployment":
			obj.SetNamespace(namespace)
			ok, err := addWatchNamespaceArg(obj, namespace)
			if err != nil {
				return nil, err
			}
			addedArg = addedArg || ok
		default:
			if obj.GetNamespace() == "" {
				return nil, xerrors.Newf("unsupported cluster-scoped object: %s/%s", obj.GetKind(), obj.GetName())
			}
			obj.SetNamespace(namespace)
		}
		converted = append(converted, obj)
	}
	if !injectedCert {
		return nil, xerrors.New("the manifest doesn't have the Secret of the webhook certificate")
	}
	if !addedArg {
		return nil, xerrors.New("the manifest doesn't have the operator container")
	}

	return converted, nil
}

func clusterScopedName(name, namespace string) string {
	return fmt.Sprintf("%s-%s", name, namespace)
}

func setSubjectsNamespace(obj *unstructured.Unstructured, namespace string) error {
	subjects, _, err := unstructured.NestedSlice(obj.Object, "subjects")
	if err != nil {
		return xerrors.WithStack(err)
	}
	for _, v := range subjects {
		s := v.(map[string]any)
		if s["kind"] == "ServiceAccount" {
			s["namespace"] = namespace
		}
	}
	return xerrors.WithStack(unstructured.SetNestedSlice(obj.Object, subjects, "subjects"))
}

func limitWebhooksToNamespace(obj *unstructured.Unstructured, namespace, caBundle string) error {
	webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
	if err != nil {
		return xerrors.WithStack(err)
	}
	for _, v := range webhooks {
		w := v.(map[string]any)
		if err := unstructured.SetNestedField(w, namespace, "clientConfig", "service", "namespace"); err != nil {
			return xerrors.WithStack(err)
		}
		if err := unstructured.SetNestedField(w, caBundle, "clientConfig", "caBundle"); err != nil {
			return xerrors.WithStack(err)
		}
		selector := map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": namespace}}
		if err := unstructured.SetNestedMap(w, selector, "namespaceSelector"); err != nil {
			return xerrors.WithStack(err)
		}
	}
	return xerrors.WithStack(unstructured.SetNestedSlice(obj.Object, webhooks, "webhooks"))
}

func addWatchNamespaceArg(obj *unstructured.Unstructured, namespace string) (bool, error) {
	containers, _, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
	if err != nil {
		return false, xerrors.WithStack(err)
	}
	added := false
	for _, v := range containers {
		c := v.(map[string]any)
		if c["name"] != "operator" {
			continue
		}
		args, _, err := unstructured.NestedStringSlice(c, "args")
		if err != nil {
			return false, xerrors.WithStack(err)
		}
		args = slices.DeleteFunc(args, func(arg string) bool { return strings.HasPrefix(arg, "--namespace=") })
		if err := unstructured.SetNestedStringSlice(c, append(args, "--namespace="+namespace), "args"); err != nil {
			return false, xerrors.WithStack(err)
		}
		added = true
	}
	if err := unstructured.SetNestedSlice(obj.Object, containers, "spec", "template", "spec", "containers"); err != nil {
		return false, xerrors.WithStack(err)
	}
	return added, nil
}

func webhookServerCertificate(caCert *x509.Certificate, caKey crypto.PrivateKey, dnsNames []string) ([]byte, []byte, error) {
	serverCert, serverKey, err := cert.GenerateServerCertificate(caCert, caKey, dnsNames)
	if err != nil {
		return nil, nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(serverKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), nil
}
