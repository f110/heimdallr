package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommand_Usage(t *testing.T) {
	c1 := &Command{
		Use:   "foo",
		Short: "This command is...",
	}
	c1.Flags().String("server", "Hostname").Shorthand("s")
	c2 := &Command{
		Use:   "bar",
		Short: "blah blah blah",
		Run: func(_ context.Context, _ *Command, _ []string) error {
			return nil
		},
	}
	c2.Flags().String("baz", "This flag is ...").Default("foobar")
	c1.AddCommand(c2)

	c3 := &Command{
		Use:   "checkout",
		Short: "blah blah blah",
	}
	c1.AddCommand(c3)

	c4 := &Command{
		Use:   "branch",
		Short: "branch name",
		Run: func(_ context.Context, _ *Command, _ []string) error {
			return nil
		},
	}
	c4.Flags().String("server", "Server name")
	c4.Flags().Int("port", "Port").Default(443)
	c4.Flags().String("ca-cert", "CA certificate file path")
	c4.Flags().Bool("insecure", "Insecure").Shorthand("k")
	c4.Flags().String("output", "Output file path").Shorthand("o")
	c4.Flags().String("input", "Input file path").Shorthand("i")
	c3.AddCommand(c4)

	assert.Contains(t, c1.Usage(), "Usage: foo [-s | --server] <command> [<args>]")
	assert.Contains(t, c2.Usage(), "Usage: foo bar [--baz] [<args>]")
	assert.Contains(t, c3.Usage(), "Usage: foo checkout <command> [<args>]")
	assert.Contains(t, c4.Usage(), "Usage: foo checkout branch [--server] [--port] [--ca-cert] [-k | --insecure] [-o | --output] [-i | --input] [<args>]")
}

func TestCommand_Execute(t *testing.T) {
	t.Run("Flags", func(t *testing.T) {
		c1 := &Command{
			Use:   "foo",
			Short: "This command is...",
		}
		c1.Flags().String("server", "Hostname").Shorthand("s")
		c2 := &Command{
			Use:   "bar",
			Short: "blah blah blah",
			Run: func(_ context.Context, _ *Command, _ []string) error {
				return nil
			},
		}
		c2.Flags().String("baz", "This flag is ...").Default("foobar")
		c1.AddCommand(c2)

		c3 := &Command{
			Use:   "checkout",
			Short: "blah blah blah",
		}
		c1.AddCommand(c3)

		var executed bool
		c4 := &Command{
			Use:   "branch",
			Short: "branch name",
			Run: func(_ context.Context, _ *Command, _ []string) error {
				executed = true
				return nil
			},
		}
		c4.Flags().Int("port", "Port").Default(443)
		c4.Flags().String("ca-cert", "CA certificate file path")
		c4.Flags().Bool("insecure", "Insecure").Shorthand("k")
		c4.Flags().String("output", "Output file path").Shorthand("o")
		c4.Flags().String("input", "Input file path").Shorthand("i")
		c3.AddCommand(c4)

		err := c1.Execute([]string{"foo", "--server", "checkout", "checkout", "branch"})
		require.NoError(t, err)
		assert.True(t, executed)
	})

	t.Run("Args", func(t *testing.T) {
		cases := [][]string{
			{"ctl", "--override", "foo", "proxy", "--insecure", "localhost"},
			{"ctl", "--override=foo", "proxy", "--insecure", "localhost"},
		}

		for _, v := range cases {
			var override string
			var insecure bool
			var args []string
			c1 := &Command{
				Use: "ctl",
			}
			c1.Flags().String("override", "").Var(&override)
			c2 := &Command{
				Use: "proxy",
				Run: func(_ context.Context, _ *Command, a []string) error {
					args = a
					return nil
				},
			}
			c2.Flags().Bool("insecure", "").Var(&insecure)
			c1.AddCommand(c2)

			err := c1.Execute(v)
			require.NoError(t, err)
			assert.Equal(t, "foo", override)
			assert.True(t, insecure)
			assert.Equal(t, []string{"localhost"}, args)
		}
	})

	t.Run("Arg", func(t *testing.T) {
		var override string
		var args []string
		c1 := &Command{
			Use: "ctl",
			Run: func(_ context.Context, _ *Command, a []string) error {
				args = a
				return nil
			},
		}
		c1.Flags().String("override", "").Var(&override)

		err := c1.Execute([]string{"ctl", "--override", "foo"})
		require.NoError(t, err)
		assert.Equal(t, "foo", override)
		assert.Equal(t, []string{}, args)
	})
}
