package release

import (
	"errors"
	"os"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			err = githubRelease(tt.Opt)
		}()

		if tt.Err != nil {
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.Err), "Got err: %v", err)
		} else {
			require.NoError(t, err)
		}
	}
}
