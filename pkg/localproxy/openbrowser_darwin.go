package localproxy

import "os/exec"

func OpenBrowser(u string) error {
	cmd := exec.Command("python", "-m", "webbrowser", u)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
