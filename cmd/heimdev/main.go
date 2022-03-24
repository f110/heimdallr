package main

import (
	"fmt"
	"os"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/heimdev"
)

func dev(args []string) error {
	rootCmd := &cmd.Command{
		Use: "heimdev",
	}

	heimdev.TestServer(rootCmd)
	heimdev.Cluster(rootCmd)
	heimdev.DNS(rootCmd)
	heimdev.Graph(rootCmd)
	heimdev.OpenIDProvider(rootCmd)

	return rootCmd.Execute(args)
}

func main() {
	if err := dev(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
