package xerrors

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"go.uber.org/zap/zapcore"
)

type Error struct {
	err        error
	msg        string
	stackTrace Frames
}

func (e *Error) Error() string {
	b := new(strings.Builder)
	b.WriteString(e.msg)
	if e.err != nil {
		if b.Len() != 0 {
			b.WriteString(": ")
		}
		fmt.Fprint(b, e.err)
	}
	return b.String()
}

func (e *Error) Unwrap() error {
	return e.err
}

func (e *Error) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if e.msg != "" {
			io.WriteString(s, e.msg)
		}
		if e.err != nil {
			if e.msg != "" {
				io.WriteString(s, ": ")
			}
			fmt.Fprint(s, e.err)
		}
		if s.Flag('+') {
			io.WriteString(s, "\n")
			io.WriteString(s, e.StackTrace().String())
		}
	}
}

// StackTrace returns Frames that is most deeply frames in the error chain.
func (e *Error) StackTrace() Frames {
	return StackTrace(e)
}

// New returns an error.
func New(msg string) error {
	return &Error{msg: msg}
}

// Newf returns an error with formatted text.
func Newf(format string, a ...any) error {
	return &Error{msg: fmt.Sprintf(format, a...)}
}

// NewWithStack returns an error with a stack trace.
func NewWithStack(msg string) error {
	return &Error{msg: msg, stackTrace: caller()}
}

// NewfWithStack returns an error with formatted text and a stack trace.
func NewfWithStack(format string, a ...any) error {
	return &Error{msg: fmt.Sprintf(format, a...), stackTrace: caller()}
}

// WithStack annotates err with a stack trace.
// If err is nil, WithStack returns nil.
func WithStack(err error) error {
	if err == nil {
		return nil
	}
	if StackTrace(err) == nil {
		return &Error{err: err, stackTrace: caller()}
	}
	return err
}

func WithMessage(err error, msg string) error {
	var st []uintptr
	if StackTrace(err) == nil {
		st = caller()
	}
	return &Error{msg: msg, err: err, stackTrace: st}
}

func WithMessagef(err error, format string, a ...any) error {
	var st []uintptr
	if StackTrace(err) == nil {
		st = caller()
	}
	return &Error{msg: fmt.Sprintf(format, a...), err: err, stackTrace: st}
}

type Frames []uintptr

var _ zapcore.ArrayMarshaler = Frames{}

func StackTrace(err error) Frames {
	var sErr *Error
	if !errors.As(err, &sErr) {
		return nil
	}
	err = sErr

	var frames Frames
	for {
		v, ok := err.(*Error)
		if ok {
			if len(frames) < len(v.stackTrace) {
				frames = v.stackTrace
			}
		}
		if err = errors.Unwrap(err); err == nil {
			break
		}
	}

	return frames
}

func (f Frames) String() string {
	s := &strings.Builder{}
	frames := runtime.CallersFrames(f)
	for {
		frame, more := frames.Next()
		if frame.Function != "" {
			fmt.Fprintf(s, "%s\n", frame.Function)
		}
		if frame.File != "" {
			fmt.Fprintf(s, "    %s:%d\n", frame.File, frame.Line)
		}
		if !more {
			break
		}
	}
	return s.String()
}

func (f Frames) Frame(i int) *Frame {
	return newFrame(f[i])
}

func (f Frames) MarshalLogArray(e zapcore.ArrayEncoder) error {
	frames := runtime.CallersFrames(f)
	for {
		frame, more := frames.Next()
		e.AppendString(fmt.Sprintf("%s:%s:%d", frame.Function, frame.File, frame.Line))
		if !more {
			break
		}
	}
	return nil
}

type Frame struct {
	Name string
	File string
	Line int
}

func newFrame(f uintptr) *Frame {
	fn := runtime.FuncForPC(f)
	file, line := fn.FileLine(f)
	return &Frame{
		Name: fn.Name(),
		File: file,
		Line: line,
	}
}

func (f *Frame) String() string {
	return fmt.Sprintf("%s %s:%d", f.Name, f.File, f.Line)
}

func caller() []uintptr {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(3, pcs)
	return pcs[:n]
}
