package main

import (
	"fmt"
	"os"

	"github.com/f110/lagrangian-proxy/pkg/localproxy"
)

func proxy(args []string) error {
	tokenClient := localproxy.NewTokenClient("token")
	token, err := tokenClient.GetToken()
	if err != nil {
		return err
	}

	client, err := localproxy.Dial(args[0], token)
	if err != nil {
		return err
	}

	return client.Pipe(os.Stdin, os.Stdout)
}

func main() {
	if err := proxy(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
