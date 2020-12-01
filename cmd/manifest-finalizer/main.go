package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
)

type basic struct {
	ApiVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

func finalizer(in io.Reader, out io.Writer, version string) error {
	d := yaml.NewDecoder(in)
	e := yaml.NewEncoder(out)
	for {
		v := make(map[interface{}]interface{})
		err := d.Decode(v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
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
			return err
		}
	}
	e.Close()

	return nil
}

func detectKind(v interface{}) (string, error) {
	b, err := yaml.Marshal(v)
	if err != nil {
		return "", err
	}
	bc := &basic{}
	if err := yaml.Unmarshal(b, bc); err != nil {
		return "", err
	}

	if bc.Kind != "" {
		return bc.Kind, nil
	}

	return "", errors.New("failed parse document")
}

func editCustomResourceDefinition(v map[interface{}]interface{}) {
	delete(v, "status")

	m := v["metadata"].(map[interface{}]interface{})
	delete(m, "creationTimestamp")
	delete(m, "annotations")
}

func editDeployment(v map[interface{}]interface{}, version string) {
	containers := v["spec"].(map[interface{}]interface{})["template"].(map[interface{}]interface{})["spec"].(map[interface{}]interface{})["containers"].([]interface{})
	for _, c := range containers {
		v := c.(map[interface{}]interface{})
		if i, ok := v["image"]; ok {
			image := i.(string)
			if strings.Contains(image, "heimdallr-operator") {
				s := strings.Split(image, ":")
				v["image"] = s[0] + ":" + version
			}
		}
	}
}

func main() {
	var in, out, version string
	pflag.CommandLine.StringVar(&in, "in", "", "Input file")
	pflag.CommandLine.StringVar(&out, "out", "", "Output path")
	pflag.CommandLine.StringVar(&version, "version", "", "Version string")
	pflag.Parse()

	reader, err := os.Open(in)
	if err != nil {
		panic(err)
	}
	writer, err := os.Create(out)
	if err != nil {
		panic(err)
	}

	if err := finalizer(reader, writer, version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
