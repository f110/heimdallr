package token

import (
	"os/exec"
	"strings"
)

// for testing
var (
	forTestMock     bool
	mockOpenBrowser string
)

func execCommand(command string, args ...string) error {
	if forTestMock {
		mockOpenBrowser = strings.Join(append([]string{command}, args...), " ")
		return nil
	}

	cmd := exec.Command(command, args...)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
