package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.f110.dev/heimdallr/pkg/cmd/heimdev"
)

func dev(args []string) error {
	rootCmd := &cobra.Command{
		Use: "heimdev",
	}

	heimdev.TestServer(rootCmd)
	heimdev.Cluster(rootCmd)
	heimdev.DNS(rootCmd)
	heimdev.Graph(rootCmd)
	heimdev.OpenIDProvider(rootCmd)

	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func main() {
	if err := dev(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
