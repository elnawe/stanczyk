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
	CodeTypecheckError
	CodeValidationError
	CodeCodegenError
	GlobalParseError
	FunctionParseError
	UsingError
	CompilationError
	CriticalError
)

const (
	ConstantValueKindNotAllowed =
		"syntax error: unknown value in constant declaration"
	DeclarationWordMissing =
		"syntax error: invalid expression in declaration"
	DeclarationWordAlreadyUsed =
		"'%s' redeclared in this program"
	StackChangedInCodeBlock =
		"stack values (size or type) can't change inside scope blocks"
	IncorrectBlockOfCodeClosingStatement =
		"syntax error: block of code not closing properly"
	NonDeclarationInGlobalScope =
		"syntax error: non-declaration statement outside of function body"
	WordMissingAfterUsing =
		"syntax error: need a valid word after keyword 'using'"
)

func ReportErrorAtEOF(msg string) {
	fmt.Fprintf(os.Stderr, "Error at end of file: %s\n", msg);
}

func ReportErrorAtLocation(orig string, loc Location, args ...any) {
	prefix := fmt.Sprintf(MsgErrorPrefix, loc.f, loc.l, loc.c)
	msg := fmt.Sprintf(orig, args...)
	fmt.Fprintf(os.Stderr, "%s %s\n", prefix, msg);
}

func ExitWithError(error ErrorCode) {
	os.Exit(int(error))
}
