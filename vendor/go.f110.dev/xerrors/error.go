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
			io.WriteString(s, e.stackTrace.String())
		}
	}
}

func New(msg string) error {
	return &Error{msg: msg, stackTrace: caller()}
}

func Newf(format string, a ...any) error {
	return &Error{msg: fmt.Sprintf(format, a...), stackTrace: caller()}
}

// WithStack annotates err with a stack trace.
// If err is nil, WithStack returns nil.
func WithStack(err error) error {
	if err == nil {
		return nil
	}
	return &Error{err: err, stackTrace: caller()}
}

func WithMessage(err error, msg string) error {
	return &Error{msg: msg, err: err, stackTrace: caller()}
}

func WithMessagef(err error, format string, a ...any) error {
	return &Error{msg: fmt.Sprintf(format, a...), err: err, stackTrace: caller()}
}

type Frames []uintptr

var _ zapcore.ArrayMarshaler = Frames{}

func StackTrace(err error) Frames {
	v, ok := err.(*Error)
	if !ok {
		return nil
	}

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

	return v.stackTrace
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
