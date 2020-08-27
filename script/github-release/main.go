package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v32/github"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

func githubRelease(args []string) error {
	var version string
	var from string
	var attach []string
	var githubRepo string
	fs := pflag.NewFlagSet("github-release", pflag.ContinueOnError)
	fs.StringVar(&version, "version", "", "")
	fs.StringVar(&from, "from", "", "")
	fs.StringArrayVar(&attach, "attach", []string{}, "")
	fs.StringVar(&githubRepo, "repo", "", "")
	if err := fs.Parse(args); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	token := os.Getenv("GITHUB_APITOKEN")
	if token == "" {
		return xerrors.New("GITHUB_APITOKEN is empty")
	}
	if !strings.Contains(githubRepo, "/") {
		return xerrors.Errorf("invalid repo name: %s", githubRepo)
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	client := github.NewClient(tc)

	r := strings.Split(githubRepo, "/")
	owner, repo := r[0], r[1]

	release, res, err := client.Repositories.GetReleaseByTag(context.Background(), owner, repo, version)
	if err != nil && res == nil {
		return xerrors.Errorf(": %w", err)
	}

	// Create new release
	attachedFiles := make(map[string]struct{})
	if release != nil {
		for _, v := range release.Assets {
			attachedFiles[v.GetName()] = struct{}{}
		}
	} else {
		branch, _, err := client.Repositories.GetBranch(context.Background(), owner, repo, from)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if branch == nil {
			return xerrors.Errorf("branch(%s) is not found", from)
		}
		fmt.Printf("Get commit hash %s\n", branch.Commit.GetSHA())

		r, _, err := client.Repositories.CreateRelease(context.Background(), owner, repo, &github.RepositoryRelease{
			TagName:         github.String(version),
			TargetCommitish: branch.Commit.SHA,
		})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		fmt.Printf("Created release id=%d TagName=%s\n", r.GetID(), r.GetTagName())
		release = r
	}

	for _, v := range attach {
		if _, err := os.Stat(v); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "%s is not found", v)
			continue
		}
		f, err := os.Open(v)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		filename := filepath.Base(f.Name())
		if _, ok := attachedFiles[filename]; ok {
			fmt.Printf("%s is already exist. skip uploading this file", filename)
			continue
		}

		assets, _, err := client.Repositories.UploadReleaseAsset(context.Background(), owner, repo, release.GetID(), &github.UploadOptions{Name: filename}, f)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if assets == nil {
			fmt.Fprintf(os.Stderr, "Failed upload an asset")
		}
		fmt.Printf("Upload asset %s\n", filename)
	}

	return nil
}

func main() {
	if err := githubRelease(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
