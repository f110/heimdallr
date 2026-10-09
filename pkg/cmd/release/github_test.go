package release

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-github/v41/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/githubmock"
)

func TestGithubRelease(t *testing.T) {
	cases := []struct {
		Opt            *githubOpt
		GithubAPIToken string
		Err            error
	}{
		{
			Opt: &githubOpt{
				GithubRepo: "f110/sandbox",
				Version:    "latest",
			},
			GithubAPIToken: "octocat",
			Err:            semver.ErrInvalidSemVer,
		},
	}

	for _, tt := range cases {
		var err error
		func() {
			if tt.GithubAPIToken != "" {
				os.Setenv("GITHUB_APITOKEN", tt.GithubAPIToken)
				defer os.Unsetenv("GITHUB_APITOKEN")
			}
			err = githubRelease(t.Context(), tt.Opt)
		}()

		if tt.Err != nil {
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.Err), "Got err: %v", err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestReleaseOnGitHub(t *testing.T) {
	caCert, caKey := setupTestCA(t)
	caCertFile, caKeyFile := writeCAFiles(t, caCert, caKey)

	dir := t.TempDir()
	binaryFile := filepath.Join(dir, "heim_linux_amd64")
	binary := []byte{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0xff, 0xfe}
	require.NoError(t, os.WriteFile(binaryFile, binary, 0644))
	manifestFile := filepath.Join(dir, "all-in-one.yaml")
	require.NoError(t, os.WriteFile(manifestFile, []byte(testManifest), 0644))
	otherManifestFile := filepath.Join(dir, "other.yaml")
	require.NoError(t, os.WriteFile(otherManifestFile, []byte(testManifest), 0644))
	bodyFile := filepath.Join(dir, "body.md")
	require.NoError(t, os.WriteFile(bodyFile, []byte("release body"), 0644))

	setup := func(t *testing.T) (*githubmock.Repository, *github.Client) {
		mock := githubmock.NewMock()
		repo := mock.Repository("f110/heimdallr")
		repo.DefaultBranch("master")
		require.NoError(t, repo.Commits(githubmock.NewCommit().IsHead().Files(&githubmock.File{Name: "README.md", Body: []byte("README")})))
		return repo, github.NewClient(&http.Client{Transport: mock.Transport()})
	}
	newOpt := func(version string) *githubOpt {
		return &githubOpt{
			Version:           version,
			From:              "master",
			Attach:            []string{binaryFile, manifestFile, otherManifestFile},
			GithubRepo:        "f110/heimdallr",
			BodyFile:          bodyFile,
			CACert:            caCertFile,
			CAKey:             caKeyFile,
			InjectWebhookCert: []string{manifestFile},
		}
	}

	t.Run("CreateRelease", func(t *testing.T) {
		repo, client := setup(t)

		err := releaseOnGitHub(t.Context(), client, newOpt("v1.0.0-rc.1"))
		require.NoError(t, err)

		release := repo.GetRelease("v1.0.0-rc.1")
		require.NotNil(t, release)
		assert.Equal(t, repo.GetCommits()[0].GetSHA(), release.GetTargetCommitish())
		assert.Equal(t, "release body", release.GetBody())
		assert.True(t, release.IsPrerelease())

		assets := releaseAssets(release)
		require.Len(t, assets, 3)
		assert.Equal(t, binary, assets["heim_linux_amd64"])
		assert.Equal(t, testManifest, string(assets["other.yaml"]))

		docs := parseAllDocs(t, assets["all-in-one.yaml"])
		require.Len(t, docs, 3)
		certPEM := docs[0]["stringData"].(map[any]any)["webhook.crt"].(string)
		block, _ := pem.Decode([]byte(certPEM))
		require.NotNil(t, block)
		serverCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.NoError(t, serverCert.CheckSignatureFrom(caCert))
	})

	t.Run("UpdateRelease", func(t *testing.T) {
		repo, client := setup(t)
		repo.Releases(
			githubmock.NewRelease().
				TagName("v1.0.0").
				Body("old body").
				Assets(&githubmock.ReleaseAsset{Name: "heim_linux_amd64", Body: []byte("uploaded")}),
		)

		err := releaseOnGitHub(t.Context(), client, newOpt("v1.0.0"))
		require.NoError(t, err)

		require.Len(t, repo.GetReleases(), 1)
		release := repo.GetRelease("v1.0.0")
		assert.Equal(t, "release body", release.GetBody())
		assert.False(t, release.IsPrerelease())

		assets := releaseAssets(release)
		require.Len(t, assets, 3)
		assert.Equal(t, []byte("uploaded"), assets["heim_linux_amd64"])
		assert.Equal(t, testManifest, string(assets["other.yaml"]))
		assert.NotEqual(t, testManifest, string(assets["all-in-one.yaml"]))
	})
}

func releaseAssets(release *githubmock.Release) map[string][]byte {
	assets := make(map[string][]byte)
	for _, v := range release.GetAssets() {
		assets[v.Name] = v.Body
	}
	return assets
}
