package release

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd"
)

func containerReleaseCmd(repository, sha256File, tag string, override bool) error {
	if tag == "" || sha256File == "" {
		return xerrors.NewWithStack("tag and sha256 is mandatory")
	}
	b, err := os.ReadFile(sha256File)
	if err != nil {
		return xerrors.WithStack(err)
	}
	sha256 := string(b)

	repo, err := name.NewRepository(repository)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if !override {
		images, err := remote.List(repo, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return xerrors.WithStack(err)
		}
		for _, v := range images {
			if v == tag {
				return xerrors.NewfWithStack("Container tag %s is already exists", v)
			}
		}
	}

	ref, err := name.ParseReference(fmt.Sprintf("%s@%s", repository, sha256))
	if err != nil {
		return xerrors.WithStack(err)
	}
	desc, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return xerrors.WithStack(err)
	}
	t, err := name.NewTag(fmt.Sprintf("%s:%s", repository, tag))
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := remote.Tag(t, desc, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return xerrors.WithStack(err)
	}
	return nil
}

func Container(rootCmd *cmd.Command) {
	repository := "ghcr.io/f110"
	sha256File := ""
	tag := ""
	override := false
	containerRelease := &cmd.Command{
		Use: "container",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return containerReleaseCmd(repository, sha256File, tag, override)
		},
	}
	containerRelease.Flags().String("repository", "Container repository name").Var(&repository).Default("ghcr.io/f110")
	containerRelease.Flags().String("sha256", "A file that contains a hash of container (e,g, sha256:4041a17506561283c28f168a0a84608bfcfe4847f7ac71cbb0c2fd354d7d4a5b)").Var(&sha256File)
	containerRelease.Flags().String("tag", "Tag name").Var(&tag)
	containerRelease.Flags().Bool("override", "Override a tag if exists").Var(&override)

	rootCmd.AddCommand(containerRelease)
}
