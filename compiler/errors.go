package skc

import (
	"fmt"
	"os"
)

type ErrorCode int

const (
	CodeOK ErrorCode = iota
	CodeCliError
	CodeParseError
	ValidationError
	CodeTypecheckError
	CodeCodegenError
	CriticalError
	ParseError
	UnhandledStackError
)

type ErrorMessage string

const (
	CompilerBug =
		"compiler bug found!"
	ConstantValueKindNotAllowed =
		"syntax error: unknown value in constant declaration"
	DeclarationWordAlreadyUsed =
		"'%s' redeclared in this program"
	DeclarationWordMissing =
		"syntax error: invalid expression in declaration, expecting a name"

	MainFunctionInvalidSignature =
		"main function can not have arguments or returns (got %d arguments and %d results)"
	MainFunctionUndefined =
		"critical error: 'main' function not defined"
	StackUnderflow =
		"stack underflow when trying to %s at line %d"
	StackUnhandled =
		"unhandled stack values at the end of function (got %d, expected %d)\n" + "\t%s"

	Unknown ErrorMessage = "unknown error, most likely a compiler bug"
)

func ReportErrorAtEOF(msg string) {
	fmt.Fprintf(os.Stderr, "Error at end of file: %s\n", msg);
}

func ReportErrorAtFunction(fn *Function, err ErrorMessage, args ...any) {
	pos := fmt.Sprintf("%s:%d:%d (%s)", fn.loc.f, fn.loc.l, fn.loc.c, fn.name)
	msg := fmt.Sprintf(string(err), args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", pos, msg)
}

func ReportErrorAtLocation(err string, loc Location, args ...any) {
	prefix := fmt.Sprintf(MsgErrorPrefix, loc.f, loc.l, loc.c)
	msg := fmt.Sprintf(err, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg);
}

func ExitWithError(error ErrorCode) {
	os.Exit(int(error))
}
