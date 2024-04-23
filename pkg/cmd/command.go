package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/template"

	"github.com/mattn/go-shellwords"
	"github.com/spf13/pflag"
	"go.f110.dev/xerrors"
)

type Command struct {
	Use   string
	Short string
	Long  string
	Run   func(ctx context.Context, cmd *Command, args []string) error

	flags    *FlagSet
	parent   *Command
	commands []*Command
	executed bool
}

func (c *Command) Usage() string {
	commandNameLen := 0
	for _, v := range c.commands {
		if len(v.Name()) > commandNameLen {
			commandNameLen = len(v.Name())
		}
	}
	name := c.Use
	parent := c.parent
	var globalFlags *FlagSet
	if parent != nil {
		globalFlags = parent.Flags().Copy()
	}
	for parent != nil {
		name = parent.Use + " " + name
		parent = parent.parent
		if parent != nil {
			globalFlags.AddFlagSet(parent.Flags())
		}
	}

	buf := new(bytes.Buffer)
	err := usageTmpl.Execute(buf, struct {
		Name              string
		Flags             *FlagSet
		OnelineFlagUsage  string
		Commands          []*Command
		CommandNameLength int
		Parent            *Command
		GlobalFlags       *FlagSet
	}{
		Name:              name,
		Flags:             c.Flags(),
		OnelineFlagUsage:  c.Flags().OnelineUsage(len("Usage: ")+len(name)+1, 80),
		Commands:          c.commands,
		CommandNameLength: commandNameLen + 3,
		Parent:            c.parent,
		GlobalFlags:       globalFlags,
	})
	if err != nil {
		panic(err)
	}

	return buf.String()
}

func (c *Command) Execute(args []string) error {
	if c.executed {
		return xerrors.NewWithStack("already executed")
	}

	c.executed = true
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cmd, nArgs := c.findCommand(args)
	if cmd != nil {
		return cmd.runCommand(ctx, nArgs)
	}
	return c.runCommand(ctx, args)
}

func (c *Command) runCommand(ctx context.Context, args []string) error {
	fs := c.Flags().Copy()
	parent := c.parent
	for parent != nil {
		fs.AddFlagSet(parent.Flags())
		parent = parent.parent
	}
	help := false
	fs.Bool("help", "Show help").Shorthand("h").Var(&help)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if help {
		c.printUsage()
		return nil
	}

	if c.Run == nil {
		c.printUsage()
		return xerrors.NewWithStack("command not found")
	}
	return c.Run(ctx, c, fs.Args())
}

func (c *Command) printUsage() {
	_, _ = fmt.Fprint(os.Stderr, c.Usage())
}

func (c *Command) Flags() *FlagSet {
	if c.flags == nil {
		c.flags = NewFlagSet("", pflag.ContinueOnError)
	}

	return c.flags
}

func (c *Command) AddCommand(cmd *Command) {
	cmd.parent = c
	c.commands = append(c.commands, cmd)
}

func (c *Command) Name() string {
	s, err := shellwords.Parse(c.Use)
	if err != nil {
		return c.Use
	}
	if len(s) > 0 {
		return s[0]
	}

	return c.Use
}

func (c *Command) findCommand(args []string) (*Command, []string) {
	const (
		stateInit = iota
		stateValue
	)

	var nArgs []string
	state := stateInit
	for i, v := range args {
		if len(v) == 0 {
			continue
		}

		switch state {
		case stateInit:
			if v[0] == '-' {
				if !strings.Contains(v, "=") {
					state = stateValue
				}
				nArgs = append(nArgs, v)
				continue
			}
		case stateValue:
			state = stateInit
			nArgs = append(nArgs, v)
			continue
		}

		for _, cmd := range c.commands {
			if cmd.Name() == v {
				return cmd.findCommand(append(nArgs, args[i+1:]...))
			}
		}
	}

	return c, nArgs
}

var usageTmpl = template.Must(
	template.New("").
		Funcs(
			map[string]interface{}{
				"left": func(width int, val string) string {
					return fmt.Sprintf("%-"+strconv.Itoa(width)+"s", val)
				},
			},
		).
		Parse(`Usage: {{ .Name }}{{ if .Flags.HasFlags }} {{ .OnelineFlagUsage }}{{ end }}{{ if .Commands }} <command>{{ end }} [<args>]
{{- if .Commands }}

Available Commands:
{{- range .Commands }}
  {{ left $.CommandNameLength .Name }}{{ .Short }}
{{- end }}
{{- end }}
{{- if gt .Flags.Len 0 }}

Options:
{{ .Flags.Usage }}
{{- end }}
{{- if .GlobalFlags }}{{- if gt .GlobalFlags.Len 0 }}

Global Options:
{{ .GlobalFlags.Usage }}
{{- end }}{{- end }}
`))
