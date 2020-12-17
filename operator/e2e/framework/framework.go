package framework

import (
	"flag"
	"testing"
	"time"

	"github.com/smartystreets/goconvey/convey"
)

var (
	beforeSuite func()
	afterSuite  func()
)

var Config = &ConfigStruct{}

type ConfigStruct struct {
	RandomSeed         int64
	ProxyVersion       string
	CRDDir             string
	ClusterVersion     string
	Verbose            bool
	KindFile           string
	ProxyImageFile     string
	RPCImageFile       string
	DashboardImageFile string
	Retain             bool
}

func Flags(fs *flag.FlagSet) {
	fs.Int64Var(&Config.RandomSeed, "random-seed", time.Now().Unix(), "Random seed")
	fs.StringVar(&Config.ProxyVersion, "proxy.version", "", "Proxy version")
	fs.StringVar(&Config.CRDDir, "crd", "", "CRD files")
	fs.BoolVar(&Config.Verbose, "verbose", false, "View controller's log")
	fs.StringVar(&Config.ClusterVersion, "cluster-version", "v0.18.8", "Kubernetes cluster version")
	fs.StringVar(&Config.KindFile, "kind-file", "", "Kind executable file path")
	fs.StringVar(&Config.ProxyImageFile, "proxy-image-file", "", "Proxy image file")
	fs.StringVar(&Config.RPCImageFile, "rpc-image-file", "", "RPC image file")
	fs.StringVar(&Config.DashboardImageFile, "dashboard-image-file", "", "Dashboard image file")
	fs.BoolVar(&Config.Retain, "retain", false, "Do not delete cluster after test")
}

func BeforeSuite(f func()) {
	beforeSuite = f
}

func AfterSuite(f func()) {
	afterSuite = f
}

func RunSpec(m *testing.M) int {
	if beforeSuite != nil {
		beforeSuite()
	}
	if afterSuite != nil {
		defer afterSuite()
	}

	return m.Run()
}

func Describe(t *testing.T, description string, action func()) {
	convey.Convey(description, t, action)
}

func Context(description string, action func()) {
	convey.Convey(description, action)
}

func It(description string, action func()) {
	convey.Convey(description, action)
}

func XIt(description string, action func()) {
	convey.SkipConvey(description, action)
}
