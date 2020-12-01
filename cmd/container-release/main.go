package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

func containerRelease(args []string) error {
	repository := "quay.io/f110"
	sha256File := ""
	tag := ""
	fs := pflag.NewFlagSet("container-release", pflag.ContinueOnError)
	fs.StringVar(&repository, "repository", repository, "Container repository name")
	fs.StringVar(&sha256File, "sha256", sha256File, "A file that contains a hash of container (e,g, sha256:4041a17506561283c28f168a0a84608bfcfe4847f7ac71cbb0c2fd354d7d4a5b)")
	fs.StringVar(&tag, "tag", tag, "Tag name")
	if err := fs.Parse(args); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if tag == "" || sha256File == "" {
		return xerrors.New("tag and sha256 is mandatory")
	}
	b, err := ioutil.ReadFile(sha256File)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	sha256 := string(b)

	repo, err := name.NewRepository(repository)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	images, err := remote.List(repo, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	for _, v := range images {
		if v == tag {
			return xerrors.Errorf("Container tag %s is already exists", v)
		}
	}
	ref, err := name.ParseReference(fmt.Sprintf("%s@%s", repository, sha256))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	desc, err := remote.Image(ref)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	t, err := name.NewTag(fmt.Sprintf("%s:%s", repository, tag))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := remote.Tag(t, desc, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func main() {
	if err := containerRelease(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
