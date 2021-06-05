package dashboard

import "embed"

//go:embed index.tmpl agent cert include me role service_account user
var Data embed.FS
