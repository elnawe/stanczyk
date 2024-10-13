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
	MacroParseError
	UsingError
	CompilationError
	CriticalError
)

const (
	BodyDefinitionEmpty =
		"body definition cannot be empty"
	BodyStackIsAlreadyTaken =
		"body stack is already in use, flush it by calling a macro first"
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
	IncorrectValuesAtReturn =
		"function '%s' has incorrect amount of values at return (got %d, expected %d)"
	IncorrectValueTypeAtReturn =
		"function '%s' is returning incorrect value types (got %s, expected %s)"
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
	StackSizeChangedInCodeBlock =
		"the size of the stack can't change inside scope blocks (was %d, and now is %d)"
	StackTypesChangedInCodeBlock =
		"the type of the values in the stack can't change inside scope blocks\n" +
			"\tbefore: %s\n\tafter: %s"
	StackUnderflow =
		"missing stack values when trying to '%s' in '%s'"
	TypeError =
		"incorrect arguments for %s\n"+
			"\thave (%s)\n\twant (%s)"
	TypeError2 =
		"incorrect arguments for %s\n"+
			"\thave (%s)\n\twant (%s) or (%s)"
	UnexpectedCodeBlockSyntax =
		"syntax error: '%s' can only be used after using %s"
	UnexpectedSymbol =
		"syntax error: unexpected symbol, expected '%s'"
	UnexpectedValueMacroBody =
		"syntax error: unexpected value in macro body"
	UnknownWord =
		"syntax error: unknown word '%s'"
	VariableValueKindNotAllowed =
		"syntax error: unknown value type in variable declaration"
	WordMissingAfterUsing =
		"syntax error: need a valid word after keyword 'using'"

	TooManyErrors = "too many errors to continue"
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
	if len(TheProgram.errors) > 0 {
		for _, e := range TheProgram.errors {
			ReportErrorAtLocation(e.message, e.token.loc)
		}
	}
	os.Exit(int(error))
}
