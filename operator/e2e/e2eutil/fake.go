package e2eutil

import (
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/f110/lagrangian-proxy/operator/e2e/data"
)

func FakeDependsOnOperators() ([]*apiextensionsv1.CustomResourceDefinition, []*apiextensionsv1beta1.CustomResourceDefinition) {
	crd := make([]*apiextensionsv1.CustomResourceDefinition, 0)
	crdBeta1 := make([]*apiextensionsv1beta1.CustomResourceDefinition, 0)
	sch := runtime.NewScheme()
	_ = apiextensionsv1.AddToScheme(sch)
	_ = apiextensionsv1beta1.AddToScheme(sch)
	codecs := serializer.NewCodecFactory(sch)
	for _, v := range data.Data {
		obj, _, err := codecs.UniversalDeserializer().Decode([]byte(v), nil, nil)
		if err != nil {
			continue
		}
		if c, ok := obj.(*apiextensionsv1.CustomResourceDefinition); ok {
			crd = append(crd, c)
		}

		if c, ok := obj.(*apiextensionsv1beta1.CustomResourceDefinition); ok {
			crdBeta1 = append(crdBeta1, c)
		}
	}

	return crd, crdBeta1
}
