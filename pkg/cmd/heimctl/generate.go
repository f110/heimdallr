package heimctl

import (
	"context"
	"errors"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"

	"go.f110.dev/heimdallr/pkg/cmd"
	proxyv1alpha1 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha1"
)

func Generate(rootCmd *cmd.Command) {
	generate := &cmd.Command{
		Use:   "generate",
		Short: "Generate something",
	}
	generate.AddCommand(generateBackendCommand())

	rootCmd.AddCommand(generate)
}

func generateBackendCommand() *cmd.Command {
	input := ""
	output := ""
	backend := &cmd.Command{
		Use:   "backend",
		Short: "Generate Backend from Service",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			sch := runtime.NewScheme()
			if err := corev1.AddToScheme(sch); err != nil {
				return err
			}
			if err := proxyv1alpha1.AddToScheme(sch); err != nil {
				return err
			}
			codecs := serializer.NewCodecFactory(sch)

			var buf []byte
			b, err := os.ReadFile(input)
			if err != nil {
				return err
			}
			buf = b

			obj, _, err := codecs.UniversalDeserializer().Decode(buf, nil, nil)
			if err != nil {
				return err
			}
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return errors.New("input is not Service")
			}
			var matchLabels map[string]string
			if len(svc.Labels) != 0 {
				matchLabels = svc.Labels
			}

			gvk := proxyv1alpha1.SchemeGroupVersion.WithKind("Backend")
			backend := &proxyv1alpha1.Backend{
				TypeMeta: metav1.TypeMeta{
					APIVersion: gvk.GroupVersion().String(),
					Kind:       gvk.Kind,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      svc.Name,
					Namespace: svc.Namespace,
				},
				Spec: proxyv1alpha1.BackendSpec{
					ServiceSelector: proxyv1alpha1.ServiceSelector{
						LabelSelector: metav1.LabelSelector{
							MatchLabels: matchLabels,
						},
						Namespace: svc.Namespace,
					},
				},
			}

			outWriter := os.Stdout
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				outWriter = f
			}
			s := json.NewSerializerWithOptions(json.DefaultMetaFactory, sch, sch, json.SerializerOptions{Yaml: true})
			return s.Encode(backend, outWriter)
		},
	}
	backend.Flags().String("input", "Input").Var(&input).Shorthand("i")
	backend.Flags().String("output", "Output").Var(&output).Shorthand("o")

	return backend
}
