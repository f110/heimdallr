package release

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-github/v41/github"
	"go.f110.dev/xerrors"
	"golang.org/x/oauth2"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/githubutil"
)

type githubOpt struct {
	Version                     string
	From                        string
	Attach                      []string
	GithubRepo                  string
	BodyFile                    string
	GitHubAppIdFile             string
	GitHubAppInstallationIdFile string
	GitHubAppId                 int64
	GitHubAppInstallationId     int64
	GitHubAppPrivateKeyFile     string
}

func githubRelease(opt *githubOpt) error {
	if v := os.Getenv("GITHUB_APP_ID_FILE"); v != "" {
		buf, err := os.ReadFile(v)
		if err != nil {
			return xerrors.WithStack(err)
		}
		appId, err := strconv.ParseInt(string(buf), 10, 64)
		if err != nil {
			return xerrors.WithStack(err)
		}
		opt.GitHubAppId = appId
	}
	if v := os.Getenv("GITHUB_INSTALLATION_ID_FILE"); v != "" {
		buf, err := os.ReadFile(v)
		if err != nil {
			return xerrors.WithStack(err)
		}
		installationId, err := strconv.ParseInt(string(buf), 10, 64)
		if err != nil {
			return xerrors.WithStack(err)
		}
		opt.GitHubAppInstallationId = installationId
	}
	if v := os.Getenv("GITHUB_PRIVATE_KEY"); v != "" {
		opt.GitHubAppPrivateKeyFile = v
	}
	var httpClient *http.Client
	if opt.GitHubAppId == 0 || opt.GitHubAppInstallationId == 0 || opt.GitHubAppPrivateKeyFile == "" {
		token := os.Getenv("GITHUB_APITOKEN")
		if token == "" {
			return xerrors.NewWithStack("GITHUB_APITOKEN is mandatory")
		}
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		httpClient = oauth2.NewClient(context.Background(), ts)
	} else {
		ghApp, err := githubutil.NewApp(opt.GitHubAppId, opt.GitHubAppInstallationId, opt.GitHubAppPrivateKeyFile)
		if err != nil {
			return err
		}
		t := githubutil.NewTransportWithApp(http.DefaultTransport, ghApp)
		httpClient = &http.Client{Transport: t}
	}
	client := github.NewClient(httpClient)

	if !strings.Contains(opt.GithubRepo, "/") {
		return xerrors.NewfWithStack("invalid repo name: %s", opt.GithubRepo)
	}
	ver, err := semver.NewVersion(opt.Version)
	if err != nil {
		return xerrors.WithStack(err)
	}
	preRelease := false
	if ver.Prerelease() != "" {
		preRelease = true
	}

	body := ""
	if _, err := os.Lstat(opt.BodyFile); !os.IsNotExist(err) {
		b, err := os.ReadFile(opt.BodyFile)
		if err != nil {
			return xerrors.WithStack(err)
		}
		body = string(b)
	}

	r := strings.Split(opt.GithubRepo, "/")
	owner, repo := r[0], r[1]

	release, res, err := client.Repositories.GetReleaseByTag(context.Background(), owner, repo, opt.Version)
	if err != nil && res == nil {
		return xerrors.WithStack(err)
	}

	// Create new release or Update the release
	attachedFiles := make(map[string]struct{})
	if release != nil {
		for _, v := range release.Assets {
			attachedFiles[v.GetName()] = struct{}{}
		}
		if release.GetBody() != body {
			release.Body = github.String(body)
			release, res, err = client.Repositories.EditRelease(context.Background(), owner, repo, release.GetID(), release)
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	} else {
		branch, _, err := client.Repositories.GetBranch(context.Background(), owner, repo, opt.From, true)
		if err != nil {
			return xerrors.WithStack(err)
		}
		if branch == nil {
			return xerrors.NewfWithStack("branch(%s) is not found", opt.From)
		}
		fmt.Printf("Get commit hash %s\n", branch.Commit.GetSHA())

		r, _, err := client.Repositories.CreateRelease(context.Background(), owner, repo, &github.RepositoryRelease{
			TagName:         github.String(opt.Version),
			TargetCommitish: branch.Commit.SHA,
			Body:            github.String(body),
			Prerelease:      github.Bool(preRelease),
		})
		if err != nil {
			return xerrors.WithStack(err)
		}
		fmt.Printf("Created release id=%d TagName=%s\n", r.GetID(), r.GetTagName())
		release = r
	}

	for _, v := range opt.Attach {
		if _, err := os.Stat(v); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "%s is not found", v)
			continue
		}
		f, err := os.Open(v)
		if err != nil {
			return xerrors.WithStack(err)
		}

		filename := filepath.Base(f.Name())
		if _, ok := attachedFiles[filename]; ok {
			fmt.Printf("%s is already exist. skip uploading this file", filename)
			continue
		}

		assets, _, err := client.Repositories.UploadReleaseAsset(context.Background(), owner, repo, release.GetID(), &github.UploadOptions{Name: filename}, f)
		if err != nil {
			return xerrors.WithStack(err)
		}
		if assets == nil {
			fmt.Fprintf(os.Stderr, "Failed upload an asset")
		}
		fmt.Printf("Upload asset %s\n", filename)
	}

	return nil
}

func GitHub(rootCmd *cmd.Command) {
	opt := githubOpt{}

	ghRelease := &cmd.Command{
		Use:   "github",
		Short: "Create GitHub Release",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return githubRelease(&opt)
		},
	}
	ghRelease.Flags().String("version", "").Var(&opt.Version)
	ghRelease.Flags().String("from", "").Var(&opt.From)
	ghRelease.Flags().StringArray("attach", "").Var(&opt.Attach)
	ghRelease.Flags().String("repo", "").Var(&opt.GithubRepo)
	ghRelease.Flags().String("body", "Release body").Var(&opt.BodyFile)
	ghRelease.Flags().String("github-app-id-file", "The file that contains GitHub App ID").Var(&opt.GitHubAppIdFile)
	ghRelease.Flags().String("github-installation-id-file", "The file that contains GitHub App Installation ID").Var(&opt.GitHubAppInstallationIdFile)
	ghRelease.Flags().Int64("github-app-id", "GitHub App ID").Var(&opt.GitHubAppId)
	ghRelease.Flags().Int64("github-installation-id", "GitHub App Installation ID").Var(&opt.GitHubAppInstallationId)
	ghRelease.Flags().String("github-private-key", "The file path of the private key for GitHub App").Var(&opt.GitHubAppPrivateKeyFile)
	rootCmd.AddCommand(ghRelease)
}
