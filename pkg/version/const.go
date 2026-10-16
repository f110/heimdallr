package version

import "github.com/Masterminds/semver/v3"

var Version = "development"

// IsNewer reports whether v is a newer release than base.
// It returns false if either v or base is not a release version (e.g. latest, development).
func IsNewer(v, base string) bool {
	newV, err := semver.NewVersion(v)
	if err != nil {
		return false
	}
	baseV, err := semver.NewVersion(base)
	if err != nil {
		return false
	}

	return newV.GreaterThan(baseV)
}
