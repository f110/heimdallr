package test

import (
	"fmt"

	"github.com/onsi/ginkgo"
)

func Fail(v ...interface{}) {
	ginkgo.Fail(fmt.Sprint(v...), 1)
}

func Failf(format string, args ...interface{}) {
	ginkgo.Fail(fmt.Sprintf(format, args...), 1)
}
