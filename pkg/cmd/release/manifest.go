package release

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"go.f110.dev/xerrors"
	"gopkg.in/yaml.v2"

	"go.f110.dev/heimdallr/pkg/cmd"
)

type basic struct {
	ApiVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

func finalizer(in io.Reader, out io.Writer, version string) error {
	d := yaml.NewDecoder(in)
	e := yaml.NewEncoder(out)
	for {
		v := make(map[any]any)
		err := d.Decode(v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return xerrors.WithStack(err)
		}

		kind, err := detectKind(v)
		if err != nil {
			return err
		}
		switch kind {
		case "CustomResourceDefinition":
			editCustomResourceDefinition(v)
		case "Deployment":
			editDeployment(v, version)
		}

		if err := e.Encode(v); err != nil {
			return xerrors.WithStack(err)
		}
	}
	if err := e.Close(); err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func detectKind(v any) (string, error) {
	b, err := yaml.Marshal(v)
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	bc := &basic{}
	if err := yaml.Unmarshal(b, bc); err != nil {
		return "", xerrors.WithStack(err)
	}

	if bc.Kind != "" {
		return bc.Kind, nil
	}

	return "", errors.New("failed parse document")
}

func editCustomResourceDefinition(v map[any]any) {
	delete(v, "status")

	m := v["metadata"].(map[any]any)
	delete(m, "creationTimestamp")
}

func editDeployment(v map[any]any, version string) {
	containers := v["spec"].(map[any]any)["template"].(map[any]any)["spec"].(map[any]any)["containers"].([]any)
	for _, c := range containers {
		v := c.(map[any]any)
		if i, ok := v["image"]; ok {
			image := i.(string)
			if strings.Contains(image, "heimdallr/operator") {
				s := strings.Split(image, ":")
				v["image"] = s[0] + ":" + version
			}
		}
	}
}

func manifestCleaner(input, output, version string) error {
	reader, err := os.Open(input)
	if err != nil {
		return xerrors.WithStack(err)
	}
	writer, err := os.Create(output)
	if err != nil {
		return xerrors.WithStack(err)
	}

	return finalizer(reader, writer, version)
}

func ManifestCleaner(rootCmd *cmd.Command) {
	input := ""
	output := ""
	version := ""
	cleaner := &cmd.Command{
		Use: "manifest-cleaner",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return manifestCleaner(input, output, version)
		},
	}
	cleaner.Flags().String("input", "Input file").Var(&input)
	cleaner.Flags().String("output", "Output path").Var(&output)
	cleaner.Flags().String("version", "Version string").Var(&version)

	rootCmd.AddCommand(cleaner)
}
