package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v2"
)

type basic struct {
	ApiVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

func finalizer(in io.Reader, out io.Writer) error {
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

func main() {
	if err := finalizer(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
