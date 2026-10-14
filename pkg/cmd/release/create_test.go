package release

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-github/v41/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/githubmock"
)

const testReleaseFile = `VERSION = "%s"
RELEASE_BRANCH = "%s"

PLATFORMS = [
    "linux_amd64",
]
`

func TestCreateRelease(t *testing.T) {
	releaseFile := func(version, branch string) *githubmock.File {
		return &githubmock.File{Name: "build/root/RELEASE.bzl", Body: fmt.Appendf(nil, testReleaseFile, version, branch)}
	}
	setup := func(t *testing.T) (*githubmock.Repository, *github.Client) {
		mock := githubmock.NewMock()
		repo := mock.Repository("f110/heimdallr")
		repo.DefaultBranch("master")
		require.NoError(t, repo.Commits(githubmock.NewCommit().IsHead().Files(releaseFile("latest", "master"))))
		return repo, github.NewClient(&http.Client{Transport: mock.Transport()})
	}
	setupReleaseBranch := func(t *testing.T, repo *githubmock.Repository, version string) *githubmock.Commit {
		commit := githubmock.NewCommit().Parents(repo.GetBranch("master")).Files(releaseFile(version, "release-v1.0"))
		require.NoError(t, repo.Commits(commit))
		repo.Branch("release-v1.0", commit)
		return commit
	}
	newOpt := func(version string) *createOpt {
		return &createOpt{Version: version, GithubRepo: "f110/heimdallr", ReleaseFile: "build/root/RELEASE.bzl"}
	}
	getReleaseFile := func(t *testing.T, client *github.Client, ref string) string {
		file, _, _, err := client.Repositories.GetContents(t.Context(), "f110", "heimdallr", "build/root/RELEASE.bzl", &github.RepositoryContentGetOptions{Ref: ref})
		require.NoError(t, err)
		content, err := file.GetContent()
		require.NoError(t, err)
		return content
	}
	getParentSHA := func(t *testing.T, client *github.Client, sha string) string {
		commit, _, err := client.Git.GetCommit(t.Context(), "f110", "heimdallr", sha)
		require.NoError(t, err)
		require.Len(t, commit.Parents, 1)
		return commit.Parents[0].GetSHA()
	}

	t.Run("NewReleaseBranch", func(t *testing.T) {
		repo, client := setup(t)
		master := repo.GetBranch("master")

		err := createRelease(t.Context(), client, newOpt("v1.0.0-alpha.1"))
		require.NoError(t, err)

		branch := repo.GetBranch("release-v1.0")
		require.NotNil(t, branch)
		assert.Equal(t, master.GetSHA(), getParentSHA(t, client, branch.GetSHA()))
		assert.Equal(t, fmt.Sprintf(testReleaseFile, "v1.0.0-alpha.1", "release-v1.0"), getReleaseFile(t, client, "release-v1.0"))
		assert.Equal(t, master, repo.GetBranch("master"))
		assert.Equal(t, fmt.Sprintf(testReleaseFile, "latest", "master"), getReleaseFile(t, client, "master"))

		release := repo.GetRelease("v1.0.0-alpha.1")
		require.NotNil(t, release)
		assert.Equal(t, branch.GetSHA(), release.GetTargetCommitish())
		assert.True(t, release.IsPrerelease())
	})

	t.Run("ExistingReleaseBranch", func(t *testing.T) {
		repo, client := setup(t)
		base := setupReleaseBranch(t, repo, "v1.0.0-rc.1")

		err := createRelease(t.Context(), client, newOpt("v1.0.0"))
		require.NoError(t, err)

		branch := repo.GetBranch("release-v1.0")
		require.NotNil(t, branch)
		assert.Equal(t, base.GetSHA(), getParentSHA(t, client, branch.GetSHA()))
		assert.Equal(t, fmt.Sprintf(testReleaseFile, "v1.0.0", "release-v1.0"), getReleaseFile(t, client, "release-v1.0"))

		release := repo.GetRelease("v1.0.0")
		require.NotNil(t, release)
		assert.Equal(t, branch.GetSHA(), release.GetTargetCommitish())
		assert.False(t, release.IsPrerelease())
	})

	t.Run("ReleaseFileIsUpToDate", func(t *testing.T) {
		repo, client := setup(t)
		base := setupReleaseBranch(t, repo, "v1.0.0")

		err := createRelease(t.Context(), client, newOpt("v1.0.0"))
		require.NoError(t, err)

		assert.Equal(t, base, repo.GetBranch("release-v1.0"))
		release := repo.GetRelease("v1.0.0")
		require.NotNil(t, release)
		assert.Equal(t, base.GetSHA(), release.GetTargetCommitish())
	})

	t.Run("ReleaseAlreadyExists", func(t *testing.T) {
		repo, client := setup(t)
		base := setupReleaseBranch(t, repo, "v1.0.0")
		repo.Releases(githubmock.NewRelease().TagName("v1.0.0"))

		err := createRelease(t.Context(), client, newOpt("v1.0.0"))
		require.Error(t, err)
		assert.Equal(t, base, repo.GetBranch("release-v1.0"))
		assert.Len(t, repo.GetReleases(), 1)
	})

	t.Run("PatchReleaseWithoutReleaseBranch", func(t *testing.T) {
		repo, client := setup(t)

		err := createRelease(t.Context(), client, newOpt("v1.0.1"))
		require.Error(t, err)
		assert.Nil(t, repo.GetBranch("release-v1.0"))
		assert.Empty(t, repo.GetReleases())
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		for _, v := range []string{"latest", "1.0.0", "v1.0", ""} {
			repo, client := setup(t)

			err := createRelease(t.Context(), client, newOpt(v))
			require.Error(t, err, "version=%s", v)
			assert.Empty(t, repo.GetReleases())
		}
	})
}
