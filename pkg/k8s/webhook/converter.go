package webhook

import (
	"fmt"

	"go.uber.org/zap"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"go.f110.dev/heimdallr/pkg/logger"
)

var DefaultConverter = newConverter()

type ConvertFunc func(runtime.Object) (runtime.Object, error)

type Converter struct {
	convertFuncs map[string]map[string]ConvertFunc
}

func newConverter() *Converter {
	return &Converter{convertFuncs: make(map[string]map[string]ConvertFunc)}
}

func (c *Converter) Register(from *schema.GroupVersionKind, to *schema.GroupVersion, f ConvertFunc) {
	if v, ok := c.convertFuncs[from.String()]; ok {
		v[to.String()] = f
	} else {
		c.convertFuncs[from.String()] = map[string]ConvertFunc{to.String(): f}
	}
}

func (c *Converter) Convert(in *apiextensionsv1.ConversionRequest) *apiextensionsv1.ConversionResponse {
	gk, err := schema.ParseGroupVersion(in.DesiredAPIVersion)
	if err != nil {
		logger.Log.Warn("Failed DesiredAPIVersion as GroupVersion",
			zap.Error(err), zap.String("DesiredAPIVersion", in.DesiredAPIVersion))
		return c.failureResponse(in.UID)
	}

	convertedObjects := make([]runtime.RawExtension, 0)
	for _, v := range in.Objects {
		obj, gvk, err := unstructured.UnstructuredJSONScheme.Decode(v.Raw, nil, nil)
		if err != nil {
			logger.Log.Warn("Failed decode object", zap.Error(err))
			return c.failureResponse(in.UID)
		}
		convertedObj, err := c.convert(gvk, &gk, obj)
		if err != nil {
			res := c.failureResponse(in.UID)
			res.Result.Message = fmt.Sprintf("%v", err)
			return res
		}
		if convertedObj == nil {
			convertedObjects = append(convertedObjects, v)
			continue
		}

		if accessor, ok := obj.(metav1.Object); ok {
			logger.Log.Debug("Converted an object",
				zap.String("kind", gvk.Kind),
				zap.String("name", accessor.GetName()),
				zap.String("namespace", accessor.GetNamespace()),
				zap.String("desire", gk.String()),
			)
		}

		convertedObjects = append(convertedObjects, runtime.RawExtension{Object: convertedObj})
	}

	return &apiextensionsv1.ConversionResponse{
		UID:              in.UID,
		ConvertedObjects: convertedObjects,
		Result:           metav1.Status{Status: metav1.StatusSuccess},
	}
}

func (c *Converter) convert(from *schema.GroupVersionKind, to *schema.GroupVersion, obj runtime.Object) (runtime.Object, error) {
	converter, ok := c.convertFuncs[from.String()]
	if !ok {
		logger.Log.Debug("Converter not found", zap.String("from", from.String()), zap.String("to", to.String()))
		return nil, nil
	}
	if f, ok := converter[to.String()]; !ok {
		logger.Log.Debug("Converter not found", zap.String("from", from.String()), zap.String("to", to.String()))
		return nil, nil
	} else {
		return f(obj)
	}
}

func (c *Converter) failureResponse(uid types.UID) *apiextensionsv1.ConversionResponse {
	return &apiextensionsv1.ConversionResponse{
		UID: uid,
		Result: metav1.Status{
			Status: metav1.StatusFailure,
		},
	}
}
