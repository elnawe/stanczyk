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
	DeclarationWordAlreadyUsed =
		"'%s' redeclared in this program"
	DeclarationWordMissing =
		"syntax error: invalid expression in declaration, expecting a name"
	FunctionDeclarationNotFound =
		"compilation error: function declaration not found or already parsed"
	FunctionSignatureAlreadyExists =
		"function with name '%s' already exists at %s:%d:%d with the same signature"
	FunctionSignatureDifferentReturns =
		"polymorphic function with name '%s' has a different return in definition at %s:%d:%d"
	IncorrectBlockOfCodeClosingStatement =
		"syntax error: block of code not closing properly"
	MainFunctionInvalidSignature =
		"main function can not have arguments or returns"
	MainFunctionRedefined =
		"redefinition of main function found"
	NonDeclarationInGlobalScope =
		"syntax error: non-declaration statement outside of function body"
	ParameterAnyOnNonInternalFunction =
		"'any' is not a valid parameter outside of Stańczyk internal functions"
	ParameterTypeUnknown =
		"syntax error: cannot parse this parameter type"
	ParameterVariadicOnlyInArguments =
		"variadic parameter '%s' should only be used in arguments, maybe you want to use '%s' instead"
	ParameterVariadicNotFound =
		"variadic parameter '%s' definition not found in arguments"
	StackChangedInCodeBlock =
		"stack values (size or type) can't change inside scope blocks"
	UnexpectedSymbol =
		"syntax error: unexpected symbol, expected '%s'"
	VariableValueKindNotAllowed =
		"syntax error: unknown value type in variable declaration"
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
