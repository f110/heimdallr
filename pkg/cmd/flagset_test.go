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
		foo, bar, baz, piyo := "bar", "bar", "bar", "bar"
		fs.String("foo", "Usage foo").Var(&foo)
		fs.String("bar", "Usage bar").Var(&bar).Shorthand("b")
		fs.String("baz", "Usage baz").Var(&baz).Default("foo")
		fs.String("piyo", "Usage piyo").Default("foo").Var(&piyo)
		err := fs.Parse([]string{"cmd", "--foo", t.Name(), "-b", "baz"})
		require.NoError(t, err)
		assert.Equal(t, t.Name(), foo)
		assert.Equal(t, "baz", bar)
		assert.Equal(t, "foo", baz)
		assert.Equal(t, "foo", piyo)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.String("foo", "Usage foo").Required()
		fs.String("bar", "Usage bar").Required()
		fs.String("baz", "Usage baz")
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})

	t.Run("Int", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		foo, bar, baz := 1, 2, 3
		fs.Int("foo", "Usage foo").Var(&foo).Default(1)
		fs.Int("bar", "Usage bar").Var(&bar).Shorthand("b").Default(2)
		fs.Int("baz", "Usage baz").Var(&baz).Default(5)
		err := fs.Parse([]string{"cmd", "--foo", "10", "-b", "100"})
		require.NoError(t, err)
		assert.Equal(t, 10, foo)
		assert.Equal(t, 100, bar)
		assert.Equal(t, 5, baz)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.Int("foo", "Usage foo").Required()
		fs.Int("bar", "Usage bar").Required()
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})

	t.Run("Float32", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		var foo, bar, baz float32
		fs.Float32("foo", "Usage foo").Var(&foo).Default(2.0)
		fs.Float32("bar", "Usage bar").Var(&bar).Shorthand("b").Default(2.0)
		fs.Float32("baz", "Usage baz").Var(&baz).Default(10.0)
		err := fs.Parse([]string{"cmd", "--foo", "3.0", "-b", "4.0"})
		require.NoError(t, err)
		assert.Equal(t, float32(10.0), baz)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.Float32("foo", "Usage foo").Required()
		fs.Float32("bar", "Usage bar").Shorthand("b").Required()
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})

	t.Run("Bool", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		var foo, bar, baz bool
		fs.Bool("foo", "Usage foo").Var(&foo)
		fs.Bool("bar", "Usage bar").Var(&bar).Shorthand("b")
		fs.Bool("baz", "Usage baz").Var(&baz).Default(true)
		err := fs.Parse([]string{"cmd", "--foo", "-b"})
		require.NoError(t, err)
		assert.True(t, foo)
		assert.True(t, bar)
		assert.True(t, baz)
	})

	t.Run("Duration", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		foo, bar, baz := 1*time.Second, 10*time.Second, 1*time.Minute
		fs.Duration("foo", "Usage foo").Var(&foo).Default(1 * time.Second)
		fs.Duration("bar", "Usage bar").Var(&bar).Shorthand("b").Default(10 * time.Second)
		fs.Duration("baz", "Usage baz").Var(&baz).Default(1 * time.Second)
		err := fs.Parse([]string{"cmd", "--foo", "1m", "-b", "1h"})
		require.NoError(t, err)
		assert.Equal(t, 1*time.Minute, foo)
		assert.Equal(t, 1*time.Hour, bar)
		assert.Equal(t, 1*time.Second, baz)

		fs = NewFlagSet("cmd", pflag.ContinueOnError)
		fs.Duration("foo", "Usage foo").Required()
		fs.Duration("bar", "Usage bar").Required()
		err = fs.Parse([]string{"cmd"})
		require.Error(t, err)
		assert.EqualError(t, err, "required flags \"foo, bar\" not set")
	})

	t.Run("StringArray", func(t *testing.T) {
		fs := NewFlagSet("cmd", pflag.ContinueOnError)
		var foo, bar []string
		fs.StringArray("foo", "Usage foo").Var(&foo)
		fs.StringArray("bar", "Usage bar").Var(&bar).Default([]string{"foo", "good"})
		err := fs.Parse([]string{"cmd", "--foo", "bar", "--foo", "baz"})
		require.NoError(t, err)

		assert.Equal(t, []string{"bar", "baz"}, foo)
		assert.Equal(t, []string{"foo", "good"}, bar)
	})
}
