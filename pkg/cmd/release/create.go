package release

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-github/v41/github"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd"
)

type createOpt struct {
	githubAppOpt
	Version     string
	GithubRepo  string
	ReleaseFile string
}

var (
	releaseVersionPattern = regexp.MustCompile(`(?m)^VERSION = ".*"$`)
	releaseBranchPattern  = regexp.MustCompile(`(?m)^RELEASE_BRANCH = ".*"$`)
)

// createRelease creates GitHub Release of the version on the release branch (release-vX.Y).
// The release branch is created from the default branch when it doesn't exist yet,
// and VERSION and RELEASE_BRANCH in the release file are updated on the release branch before creating the release.
func createRelease(ctx context.Context, client *github.Client, opt *createOpt) error {
	owner, repo, ok := strings.Cut(opt.GithubRepo, "/")
	if !ok {
		return xerrors.NewfWithStack("invalid repo name: %s", opt.GithubRepo)
	}
	if !strings.HasPrefix(opt.Version, "v") {
		return xerrors.NewfWithStack("version must start with v: %s", opt.Version)
	}
	ver, err := semver.StrictNewVersion(strings.TrimPrefix(opt.Version, "v"))
	if err != nil {
		return xerrors.WithStack(err)
	}
	branchName := fmt.Sprintf("release-v%d.%d", ver.Major(), ver.Minor())

	if _, res, err := client.Repositories.GetReleaseByTag(ctx, owner, repo, opt.Version); err == nil {
		return xerrors.NewfWithStack("release %s already exists", opt.Version)
	} else if res == nil || res.StatusCode != http.StatusNotFound {
		return xerrors.WithStack(err)
	}

	head, err := releaseBranchHead(ctx, client, owner, repo, branchName, ver)
	if err != nil {
		return err
	}

	file, _, _, err := client.Repositories.GetContents(ctx, owner, repo, opt.ReleaseFile, &github.RepositoryContentGetOptions{Ref: head})
	if err != nil {
		return xerrors.WithStack(err)
	}
	content, err := file.GetContent()
	if err != nil {
		return xerrors.WithStack(err)
	}
	updated, err := updateReleaseFile(content, opt.Version, branchName)
	if err != nil {
		return err
	}
	target := head
	if updated != content {
		res, _, err := client.Repositories.UpdateFile(ctx, owner, repo, opt.ReleaseFile, &github.RepositoryContentFileOptions{
			Message: new(fmt.Sprintf("Release %s", opt.Version)),
			Content: []byte(updated),
			SHA:     file.SHA,
			Branch:  new(branchName),
		})
		if err != nil {
			return xerrors.WithStack(err)
		}
		target = res.Commit.GetSHA()
		fmt.Printf("Updated %s on %s: %s\n", opt.ReleaseFile, branchName, target)
	}

	release, _, err := client.Repositories.CreateRelease(ctx, owner, repo, &github.RepositoryRelease{
		TagName:         new(opt.Version),
		TargetCommitish: new(target),
		Prerelease:      new(ver.Prerelease() != ""),
	})
	if err != nil {
		return xerrors.WithStack(err)
	}
	fmt.Printf("Created release id=%d TagName=%s\n", release.GetID(), release.GetTagName())
	return nil
}

// releaseBranchHead returns the commit SHA of the release branch.
// The release branch is created from the default branch only for vX.Y.0 because the patch release must be based on the existing release branch.
func releaseBranchHead(ctx context.Context, client *github.Client, owner, repo, branchName string, ver *semver.Version) (string, error) {
	branch, res, err := client.Repositories.GetBranch(ctx, owner, repo, branchName, true)
	if err == nil {
		return branch.GetCommit().GetSHA(), nil
	}
	if res == nil || res.StatusCode != http.StatusNotFound {
		return "", xerrors.WithStack(err)
	}
	if ver.Patch() != 0 {
		return "", xerrors.NewfWithStack("%s is not found. The release branch can be created only for vX.Y.0", branchName)
	}

	r, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	defaultBranch, _, err := client.Repositories.GetBranch(ctx, owner, repo, r.GetDefaultBranch(), true)
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	ref, _, err := client.Git.CreateRef(ctx, owner, repo, &github.Reference{
		Ref:    new("refs/heads/" + branchName),
		Object: &github.GitObject{SHA: defaultBranch.GetCommit().SHA},
	})
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	fmt.Printf("Created %s from %s: %s\n", branchName, r.GetDefaultBranch(), ref.GetObject().GetSHA())
	return ref.GetObject().GetSHA(), nil
}

func updateReleaseFile(content, version, branch string) (string, error) {
	if !releaseVersionPattern.MatchString(content) || !releaseBranchPattern.MatchString(content) {
		return "", xerrors.NewWithStack("VERSION or RELEASE_BRANCH is not found in the release file")
	}
	content = releaseVersionPattern.ReplaceAllLiteralString(content, fmt.Sprintf("VERSION = %q", version))
	content = releaseBranchPattern.ReplaceAllLiteralString(content, fmt.Sprintf("RELEASE_BRANCH = %q", branch))
	return content, nil
}

func Create(rootCmd *cmd.Command) {
	opt := createOpt{}

	c := &cmd.Command{
		Use:   "create",
		Short: "Create the release branch and GitHub Release of the version",
		Run: func(ctx context.Context, _ *cmd.Command, _ []string) error {
			client, err := newGitHubClient(ctx, &opt.githubAppOpt)
			if err != nil {
				return err
			}
			return createRelease(ctx, client, &opt)
		},
	}
	c.Flags().String("version", "Release version (e.g. v0.18.0-alpha.1)").Var(&opt.Version).Required()
	c.Flags().String("repo", "Repository name (e.g. f110/heimdallr)").Var(&opt.GithubRepo).Required()
	c.Flags().String("release-file", "The path of RELEASE.bzl in the repository").Var(&opt.ReleaseFile).Default("build/root/RELEASE.bzl")
	opt.githubAppOpt.flags(c)
	rootCmd.AddCommand(c)
}
