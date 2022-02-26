package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

type FlagSet struct {
	flagSet *pflag.FlagSet

	added bool
	flags []flag
}

type flag interface {
	Flag() *pflag.Flag
}

func NewFlagSet(name string, errorHandling pflag.ErrorHandling) *FlagSet {
	return &FlagSet{flagSet: pflag.NewFlagSet(name, errorHandling)}
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
		if _, ok := flag.Flag().Annotations[flagAnnotationKeyRequired]; !ok {
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

func (fs *FlagSet) String(name, value, usage string) *StringFlag {
	f := NewStringFlag(name, value, usage)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Int(name string, value int, usage string) *IntFlag {
	f := NewIntFlag(name, value, usage)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Uint(name string, value uint, usage string) *UintFlag {
	f := NewUintFlag(name, value, usage)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Bool(name string, value bool, usage string) *BoolFlag {
	f := NewBoolFlag(name, value, usage)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Duration(name string, value time.Duration, usage string) *DurationFlag {
	f := NewDurationFlag(name, value, usage)
	fs.flags = append(fs.flags, f)
	return f
}

func (fs *FlagSet) Float32(name string, value float32, usage string) *Float32Flag {
	f := NewFloat32Flag(name, value, usage)
	fs.flags = append(fs.flags, f)
	return f
}

const (
	flagAnnotationKeyRequired = "cmd_flag_required"
)

type StringFlag struct {
	flag *pflag.Flag
}

func NewStringFlag(name, defaultValue, usage string) *StringFlag {
	return &StringFlag{
		flag: &pflag.Flag{
			Name:     name,
			DefValue: defaultValue,
			Usage:    usage,
			Value:    (*stringValue)(new(string)),
		},
	}
}

func (f *StringFlag) Shorthand(p string) *StringFlag {
	f.flag.Shorthand = p
	return f
}

func (f *StringFlag) Var(p *string) *StringFlag {
	f.flag.Value = (*stringValue)(p)
	return f
}

func (f *StringFlag) Required() *StringFlag {
	setAnnotationRequired(f.flag)
	return f
}

func (f *StringFlag) Deprecated(msg string) *StringFlag {
	f.flag.Deprecated = msg
	f.flag.Hidden = true
	return f
}

func (f *StringFlag) ShorthandDeprecated(msg string) *StringFlag {
	f.flag.ShorthandDeprecated = msg
	return f
}

func (f *StringFlag) Hidden() *StringFlag {
	f.flag.Hidden = true
	return f
}

func (f *StringFlag) Value() string {
	return f.flag.Value.String()
}

func (f *StringFlag) Flag() *pflag.Flag {
	return f.flag
}

type IntFlag struct {
	flag *pflag.Flag
}

func NewIntFlag(name string, defaultValue int, usage string) *IntFlag {
	return &IntFlag{
		flag: &pflag.Flag{
			Name:     name,
			DefValue: fmt.Sprintf("%d", defaultValue),
			Usage:    usage,
			Value:    (*intValue)(new(int)),
		},
	}
}

func (f *IntFlag) Shorthand(p string) *IntFlag {
	f.flag.Shorthand = p
	return f
}

func (f *IntFlag) Var(p *int) *IntFlag {
	f.flag.Value = (*intValue)(p)
	return f
}

func (f *IntFlag) Required() *IntFlag {
	setAnnotationRequired(f.flag)
	return f
}

func (f *IntFlag) Deprecated(msg string) *IntFlag {
	f.flag.Deprecated = msg
	f.flag.Hidden = true
	return f
}

func (f *IntFlag) ShorthandDeprecated(msg string) *IntFlag {
	f.flag.ShorthandDeprecated = msg
	return f
}

func (f *IntFlag) Hidden() *IntFlag {
	f.flag.Hidden = true
	return f
}

func (f *IntFlag) Value() string {
	return f.flag.Value.String()
}

func (f *IntFlag) Flag() *pflag.Flag {
	return f.flag
}

type UintFlag struct {
	flag *pflag.Flag
}

func NewUintFlag(name string, defaultValue uint, usage string) *UintFlag {
	return &UintFlag{
		flag: &pflag.Flag{
			Name:     name,
			DefValue: fmt.Sprintf("%d", defaultValue),
			Usage:    usage,
			Value:    (*uintValue)(new(uint)),
		},
	}
}

func (f *UintFlag) Shorthand(p string) *UintFlag {
	f.flag.Shorthand = p
	return f
}

func (f *UintFlag) Var(p *uint) *UintFlag {
	f.flag.Value = (*uintValue)(p)
	return f
}

func (f *UintFlag) Required() *UintFlag {
	setAnnotationRequired(f.flag)
	return f
}

func (f *UintFlag) Deprecated(msg string) *UintFlag {
	f.flag.Deprecated = msg
	f.flag.Hidden = true
	return f
}

func (f *UintFlag) ShorthandDeprecated(msg string) *UintFlag {
	f.flag.ShorthandDeprecated = msg
	return f
}

func (f *UintFlag) Hidden() *UintFlag {
	f.flag.Hidden = true
	return f
}

func (f *UintFlag) Value() string {
	return f.flag.Value.String()
}

func (f *UintFlag) Flag() *pflag.Flag {
	return f.flag
}

type BoolFlag struct {
	flag *pflag.Flag
}

func NewBoolFlag(name string, defaultValue bool, usage string) *BoolFlag {
	return &BoolFlag{
		flag: &pflag.Flag{
			Name:        name,
			DefValue:    fmt.Sprintf("%t", defaultValue),
			Usage:       usage,
			NoOptDefVal: "true",
			Value:       (*boolValue)(new(bool)),
		},
	}
}

func (f *BoolFlag) Shorthand(p string) *BoolFlag {
	f.flag.Shorthand = p
	return f
}

func (f *BoolFlag) Var(p *bool) *BoolFlag {
	f.flag.Value = (*boolValue)(p)
	return f
}

func (f *BoolFlag) Required() *BoolFlag {
	setAnnotationRequired(f.flag)
	return f
}

func (f *BoolFlag) Deprecated(msg string) *BoolFlag {
	f.flag.Deprecated = msg
	f.flag.Hidden = true
	return f
}

func (f *BoolFlag) ShorthandDeprecated(msg string) *BoolFlag {
	f.flag.ShorthandDeprecated = msg
	return f
}

func (f *BoolFlag) Hidden() *BoolFlag {
	f.flag.Hidden = true
	return f
}

func (f *BoolFlag) Value() string {
	return f.flag.Value.String()
}

func (f *BoolFlag) Flag() *pflag.Flag {
	return f.flag
}

type DurationFlag struct {
	flag *pflag.Flag
}

func NewDurationFlag(name string, defaultValue time.Duration, usage string) *DurationFlag {
	return &DurationFlag{
		flag: &pflag.Flag{
			Name:     name,
			DefValue: defaultValue.String(),
			Usage:    usage,
			Value:    (*durationValue)(new(time.Duration)),
		},
	}
}

func (f *DurationFlag) Shorthand(p string) *DurationFlag {
	f.flag.Shorthand = p
	return f
}

func (f *DurationFlag) Var(p *time.Duration) *DurationFlag {
	f.flag.Value = (*durationValue)(p)
	return f
}

func (f *DurationFlag) Required() *DurationFlag {
	setAnnotationRequired(f.flag)
	return f
}

func (f *DurationFlag) Deprecated(msg string) *DurationFlag {
	f.flag.Deprecated = msg
	f.flag.Hidden = true
	return f
}

func (f *DurationFlag) ShorthandDeprecated(msg string) *DurationFlag {
	f.flag.ShorthandDeprecated = msg
	return f
}

func (f *DurationFlag) Hidden() *DurationFlag {
	f.flag.Hidden = true
	return f
}

func (f *DurationFlag) Value() string {
	return f.flag.Value.String()
}

func (f *DurationFlag) Flag() *pflag.Flag {
	return f.flag
}

type Float32Flag struct {
	flag *pflag.Flag
}

func NewFloat32Flag(name string, defaultValue float32, usage string) *Float32Flag {
	return &Float32Flag{
		flag: &pflag.Flag{
			Name:     name,
			DefValue: strconv.FormatFloat(float64(defaultValue), 'g', -1, 32),
			Usage:    usage,
			Value:    (*float32Value)(new(float32)),
		},
	}
}

func (f *Float32Flag) Shorthand(p string) *Float32Flag {
	f.flag.Shorthand = p
	return f
}

func (f *Float32Flag) Var(p *float32) *Float32Flag {
	f.flag.Value = (*float32Value)(p)
	return f
}

func (f *Float32Flag) Required() *Float32Flag {
	setAnnotationRequired(f.flag)
	return f
}

func (f *Float32Flag) Deprecated(msg string) *Float32Flag {
	f.flag.Deprecated = msg
	f.flag.Hidden = true
	return f
}

func (f *Float32Flag) ShorthandDeprecated(msg string) *Float32Flag {
	f.flag.ShorthandDeprecated = msg
	return f
}

func (f *Float32Flag) Hidden() *Float32Flag {
	f.flag.Hidden = true
	return f
}

func (f *Float32Flag) Value() string {
	return f.flag.Value.String()
}

func (f *Float32Flag) Flag() *pflag.Flag {
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

type stringValue string

func (s *stringValue) String() string {
	return string(*s)
}

func (s *stringValue) Set(val string) error {
	*s = stringValue(val)
	return nil
}

func (s *stringValue) Type() string {
	return "string"
}

type intValue int

func (i *intValue) String() string {
	return fmt.Sprintf("%d", *i)
}

func (i *intValue) Set(val string) error {
	v, err := strconv.ParseInt(val, 0, 32)
	if err != nil {
		return err
	}
	*i = intValue(v)
	return nil
}

func (i *intValue) Type() string {
	return "int"
}

type uintValue uint

func (i *uintValue) String() string {
	return fmt.Sprintf("%d", *i)
}

func (i *uintValue) Set(val string) error {
	v, err := strconv.ParseUint(val, 0, 32)
	if err != nil {
		return err
	}
	*i = uintValue(v)
	return nil
}

func (i *uintValue) Type() string {
	return "uint"
}

type boolValue bool

func (b *boolValue) String() string {
	return fmt.Sprintf("%t", *b)
}

func (b *boolValue) Set(val string) error {
	var v bool
	_, err := fmt.Sscanf(val, "%t", &v)
	if err != nil {
		return err
	}
	*b = boolValue(v)
	return nil
}

func (b *boolValue) Type() string {
	return "bool"
}

type durationValue time.Duration

func (d *durationValue) String() string {
	return time.Duration(*d).String()
}

func (d *durationValue) Set(val string) error {
	v, err := time.ParseDuration(val)
	if err != nil {
		return err
	}
	*d = durationValue(v)
	return nil
}

func (d *durationValue) Type() string {
	return "duration"
}

type float32Value float32

func (f *float32Value) String() string {
	return strconv.FormatFloat(float64(*f), 'g', -1, 32)
}

func (f *float32Value) Set(val string) error {
	v, err := strconv.ParseFloat(val, 32)
	if err != nil {
		return err
	}
	*f = float32Value(v)
	return nil
}

func (f *float32Value) Type() string {
	return "flaot32"
}
