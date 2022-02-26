package cmd

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlagSet(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		foo, bar := "bar", "bar"
		fs.String("foo", foo, "Usage foo").Var(&foo)
		fs.String("bar", "bar", "Usage bar").Var(&bar).Shorthand("b")
		err := fs.Parse([]string{"cmd", "--foo", t.Name(), "-b", "baz"})
		require.NoError(t, err)
		assert.Equal(t, t.Name(), foo)
		assert.Equal(t, "baz", bar)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.String("foo", "foo", "Usage foo").Required()
		fs.String("bar", "bar", "Usage bar").Required()
		fs.String("baz", "baz", "Usage baz")
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})

	t.Run("Int", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		foo, bar := 1, 2
		fs.Int("foo", foo, "Usage foo").Var(&foo)
		fs.Int("bar", bar, "Usage bar").Var(&bar).Shorthand("b")
		err := fs.Parse([]string{"cmd", "--foo", "10", "-b", "100"})
		require.NoError(t, err)
		assert.Equal(t, 10, foo)
		assert.Equal(t, 100, bar)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.Int("foo", 1, "Usage foo").Required()
		fs.Int("bar", 1, "Usage bar").Required()
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})

	t.Run("Float32", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		var foo, bar float32
		fs.Float32("foo", 2.0, "Usage foo").Var(&foo)
		fs.Float32("bar", 2.0, "Usage bar").Var(&bar).Shorthand("b")
		err := fs.Parse([]string{"cmd", "--foo", "3.0", "-b", "4.0"})
		require.NoError(t, err)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.Float32("foo", 2.0, "Usage foo").Required()
		fs.Float32("bar", 2.0, "Usage bar").Shorthand("b").Required()
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})

	t.Run("Bool", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		foo, bar := false, false
		fs.Bool("foo", false, "Usage foo").Var(&foo)
		fs.Bool("bar", false, "Usage bar").Var(&bar).Shorthand("b")
		err := fs.Parse([]string{"cmd", "--foo", "-b"})
		require.NoError(t, err)
		assert.True(t, foo)
		assert.True(t, bar)
	})

	t.Run("Duration", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		foo, bar := 1*time.Second, 10*time.Second
		fs.Duration("foo", foo, "Usage foo").Var(&foo)
		fs.Duration("bar", bar, "Usage bar").Var(&bar).Shorthand("b")
		err := fs.Parse([]string{"cmd", "--foo", "1m", "-b", "1h"})
		require.NoError(t, err)
		assert.Equal(t, 1*time.Minute, foo)
		assert.Equal(t, 1*time.Hour, bar)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.Duration("foo", foo, "Usage foo").Required()
		fs.Duration("bar", bar, "Usage bar").Required()
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})
}
