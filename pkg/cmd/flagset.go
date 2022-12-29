package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

type flagTypes interface {
	int | int64 | uint | bool | string | []string | float32 | time.Duration
}

type FlagSet struct {
	flagSet       *pflag.FlagSet
	name          string
	errorHandling pflag.ErrorHandling

	added bool
	flags []flag
}

type flag interface {
	Flag() *pflag.Flag
}

func NewFlagSet(name string, errorHandling pflag.ErrorHandling) *FlagSet {
	return &FlagSet{flagSet: pflag.NewFlagSet(name, errorHandling), name: name, errorHandling: errorHandling}
}

func (fs *FlagSet) Len() int {
	return len(fs.flags)
}

func (fs *FlagSet) Copy() *FlagSet {
	newFs := pflag.NewFlagSet(fs.name, fs.errorHandling)
	var flags []flag
	for _, v := range fs.flags {
		flags = append(flags, v)
	}
	return &FlagSet{flagSet: newFs, name: fs.name, errorHandling: fs.errorHandling, flags: flags}
}

func (fs *FlagSet) Parse(args []string) error {
	if !fs.added {
		for _, v := range fs.flags {
			fs.flagSet.AddFlag(v.Flag())
		}
		fs.added = true
	}

	if err := fs.flagSet.Parse(args); err != nil {
		return err
	}

	var missingFlags []string
	for _, flag := range fs.flags {
		if !isRequiredFlag(flag.Flag()) {
			continue
		}

		if !flag.Flag().Changed {
			missingFlags = append(missingFlags, flag.Flag().Name)
		}
	}
	if len(missingFlags) > 0 {
		return fmt.Errorf("required flags %q not set", strings.Join(missingFlags, ", "))
	}

	return nil
}

func (fs *FlagSet) Args() []string {
	return fs.flagSet.Args()
}

func (fs *FlagSet) AddFlagSet(v *FlagSet) {
	for _, f := range v.flags {
		fs.flags = append(fs.flags, f)
	}
}

func (fs *FlagSet) Usage() string {
	fs.addFlags()

	return strings.TrimRight(fs.flagSet.FlagUsagesWrapped(80), "\n")
}

func (fs *FlagSet) OnelineUsage(leftPadding, wrap int) string {
	fs.addFlags()

	var flags []string
	for _, v := range fs.flags {
		flag := v.Flag()
		if flag.Hidden {
			continue
		}

		u := fmt.Sprintf("--%s", flag.Name)
		if flag.Shorthand != "" {
			u = "-" + flag.Shorthand + " | " + u
		}
		if !isRequiredFlag(flag) {
			u = fmt.Sprintf("[%s]", u)
		}
		flags = append(flags, u)
	}

	lines := []string{""}
	for _, v := range flags {
		lineLen := len(lines[len(lines)-1])
		if lineLen+len(v) > wrap {
			lines = append(lines, "")
		}
		if len(lines[len(lines)-1]) > 0 {
			lines[len(lines)-1] += " "
		}
		lines[len(lines)-1] += v
	}
	// Add padding
	for i := range lines {
		if i == 0 {
			continue
		}
		lines[i] = strings.Repeat(" ", leftPadding) + lines[i]
	}

	return strings.Join(lines, "\n")
}

func (fs *FlagSet) HasFlags() bool {
	fs.addFlags()
	return fs.flagSet.HasFlags()
}

func (fs *FlagSet) addFlags() {
	if !fs.added {
		for _, v := range fs.flags {
			fs.flagSet.AddFlag(v.Flag())
		}
		fs.added = true
	}
}

func (fs *FlagSet) String(name, usage string) *Flag[string] {
	f := NewFlag(
		name,
		usage,
		"", func(f *FlagValue[string], in string) error {
			*f.value = in
			return nil
		},
		nil,
		func(s string) string {
			return s
		},
	)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) StringArray(name, usage string) *Flag[[]string] {
	f := NewFlag(
		name,
		usage,
		[]string{},
		func(f *FlagValue[[]string], in string) error {
			if in != "" {
				*f.value = append(*f.value, in)
			}
			return nil
		},
		func(f *pflag.Flag, v []string) error {
			if len(v) > 0 {
				for _, vv := range v {
					if err := f.Value.Set(vv); err != nil {
						return err
					}
				}
			}
			return nil
		},
		func(i []string) string {
			return fmt.Sprintf("[%s]", strings.Join(i, ", "))
		},
	)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Int(name, usage string) *Flag[int] {
	f := NewFlag(
		name,
		usage,
		0,
		func(f *FlagValue[int], in string) error {
			v, err := strconv.ParseInt(in, 0, 32)
			if err != nil {
				return err
			}
			*f.value = int(v)
			return nil
		},
		nil,
		func(i int) string {
			return fmt.Sprintf("%d", i)
		},
	)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Uint(name, usage string) *Flag[uint] {
	f := NewFlag(
		name,
		usage,
		uint(0),
		func(f *FlagValue[uint], in string) error {
			v, err := strconv.ParseUint(in, 0, 32)
			if err != nil {
				return err
			}
			*f.value = uint(v)
			return nil
		},
		nil,
		func(u uint) string {
			return fmt.Sprintf("%d", u)
		},
	)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Bool(name, usage string) *Flag[bool] {
	f := NewFlag(
		name,
		usage,
		false, func(f *FlagValue[bool], in string) error {
			var v bool
			_, err := fmt.Sscanf(in, "%t", &v)
			if err != nil {
				return err
			}
			*f.value = v
			return nil
		},
		nil,
		func(b bool) string {
			return fmt.Sprintf("%t", b)
		},
	)
	f.flag.NoOptDefVal = "true"
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Duration(name, usage string) *Flag[time.Duration] {
	f := NewFlag(
		name,
		usage,
		time.Duration(0),
		func(f *FlagValue[time.Duration], in string) error {
			v, err := time.ParseDuration(in)
			if err != nil {
				return err
			}
			*f.value = v
			return nil
		},
		nil,
		func(d time.Duration) string {
			return d.String()
		},
	)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Float32(name, usage string) *Flag[float32] {
	f := NewFlag(
		name,
		usage,
		float32(0),
		func(f *FlagValue[float32], in string) error {
			v, err := strconv.ParseFloat(in, 32)
			if err != nil {
				return err
			}
			*f.value = float32(v)
			return nil
		},
		nil,
		func(f float32) string {
			return strconv.FormatFloat(float64(f), 'g', -1, 32)
		},
	)
	fs.flags = append(fs.flags, f)
	return f
}

const (
	flagAnnotationKeyRequired = "cmd_flag_required"
)

type Flag[T flagTypes] struct {
	flag                *pflag.Flag
	defaultValue        *T
	setValueFunc        func(*FlagValue[T], string) error
	setDefaultValueFunc func(*pflag.Flag, T) error
	toStr               func(T) string
}

func NewFlag[T flagTypes](name, usage string, defaultValue T, setValueFunc func(*FlagValue[T], string) error, setDefaultValueFunc func(*pflag.Flag, T) error, toStr func(T) string) *Flag[T] {
	return &Flag[T]{
		flag: &pflag.Flag{
			Name:  name,
			Usage: usage,
			Value: newFlagValue(new(T), setValueFunc, toStr),
		},
		defaultValue:        &defaultValue,
		setValueFunc:        setValueFunc,
		setDefaultValueFunc: setDefaultValueFunc,
		toStr:               toStr,
	}
}

func (f *Flag[T]) Var(p *T) *Flag[T] {
	f.flag.Value = newFlagValue(p, f.setValueFunc, f.toStr)
	if f.defaultValue != nil {
		if f.setDefaultValueFunc != nil {
			_ = f.setDefaultValueFunc(f.flag, *p)
		} else {
			_ = f.flag.Value.Set(f.flag.DefValue)
		}
	}

	return f
}

func (f *Flag[T]) Shorthand(p string) *Flag[T] {
	f.flag.Shorthand = p
	return f
}

func (f *Flag[T]) Required() *Flag[T] {
	setAnnotationRequired(f.flag)
	return f
}

func (f *Flag[T]) Deprecated(msg string) *Flag[T] {
	f.flag.Deprecated = msg
	f.flag.Hidden = true
	return f
}

func (f *Flag[T]) ShorthandDeprecated(msg string) *Flag[T] {
	f.flag.ShorthandDeprecated = msg
	return f
}

func (f *Flag[T]) Hidden() *Flag[T] {
	f.flag.Hidden = true
	return f
}

func (f *Flag[T]) Default(defaultValue T) *Flag[T] {
	f.flag.DefValue = f.toStr(defaultValue)
	f.defaultValue = &defaultValue
	if f.setDefaultValueFunc != nil {
		_ = f.setDefaultValueFunc(f.flag, defaultValue)
	} else {
		_ = f.flag.Value.Set(f.flag.DefValue)
	}
	return f
}

func (f *Flag[_]) Value() string {
	return f.flag.Value.String()
}

func (f *Flag[_]) Flag() *pflag.Flag {
	return f.flag
}

func setAnnotationRequired(flag *pflag.Flag) {
	if flag.Annotations == nil {
		flag.Annotations = make(map[string][]string)
	}
	if _, ok := flag.Annotations[flagAnnotationKeyRequired]; ok {
		return
	}
	flag.Annotations[flagAnnotationKeyRequired] = []string{"true"}
}

func isRequiredFlag(flag *pflag.Flag) bool {
	if _, ok := flag.Annotations[flagAnnotationKeyRequired]; ok {
		return true
	}

	return false
}

type FlagValue[T flagTypes] struct {
	value   *T
	setFunc func(*FlagValue[T], string) error
	toStr   func(T) string
}

func newFlagValue[T flagTypes](in *T, setValueFunc func(*FlagValue[T], string) error, toStr func(T) string) *FlagValue[T] {
	return &FlagValue[T]{value: in, setFunc: setValueFunc, toStr: toStr}
}

func (f *FlagValue[T]) String() string {
	return f.toStr(*f.value)
}

func (f *FlagValue[T]) Set(val string) error {
	return f.setFunc(f, val)
}

func (f *FlagValue[T]) Type() string {
	return fmt.Sprintf("%T", f.value)
}
