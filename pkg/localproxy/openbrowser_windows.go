package localproxy

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func OpenBrowser(u string) error {
	cmd := exec.Command("cmd", "/c", "start", strings.Replace(u, "&", "^&", -1))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return nil
}
