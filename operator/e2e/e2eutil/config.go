package e2eutil

import (
	"flag"
)

type Config struct {
	ProxyVersion string
}

func Flags(fs *flag.FlagSet, c *Config) {
	fs.StringVar(&c.ProxyVersion, "proxy.version", "v0.5.0", "Proxy version")
}
