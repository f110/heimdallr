package main

import (
	"fmt"
	"os"

	"go.f110.dev/heimdallr/pkg/cmd/dockercredential"
)

func main() {
	h, err := dockercredential.New()
	if err != nil {
		fmt.Fprintln(os.Stdout, err.Error())
		os.Exit(1)
	}

	os.Exit(h.Run(os.Args[1:], os.Stdin, os.Stdout))
}
