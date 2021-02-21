package token

func OpenBrowser(u, commandOverride string) error {
	if commandOverride != "" {
		return execCommand(commandOverride, u)
	}
	return execCommand("python", "-m", "webbrowser", u)
}
