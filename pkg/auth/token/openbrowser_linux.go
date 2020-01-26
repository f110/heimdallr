package token

func OpenBrowser(u string) error {
	return execCommand("python", "-m", "webbrowser", u)
}
