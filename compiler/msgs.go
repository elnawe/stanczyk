package skc

const (
	TodoRemoveCliCannotGetDirectory = "Unable to find compiler directory, this is required to make the compiler work, and if not provided we cannot continue. [COMPILER BUG]\n\nFile Reporting: %s\nOS Reported error: %s"

	MsgCliPrefix = "[Stanczyk] "
	MsgErrorPrefix = "%s:%d:%d:"


	MsgCliUnknownArgument =
		"argument %s is not a known argument. Please, check the allowed arguments by using: skc help"
	MsgCliUnknownCommand =
		"first argument should be a known command, but instead got %s\nE.g.\n" +
			"\tskc run myfile.sk\n" +
			"\t    ^^^"
	MsgCliWelcome =
		"Usage:\n" +
			"\tskc <command> [arguments]\n" +
			"Commands:\n" +
			"\tbuild  compile the entry .sk file and it's includes.\n" +
			"\trun    same as 'build', but it runs the result and cleans up the executable.\n\n" +
			"For more information about what the compiler can do, you can use: skc help.\n"


	/*    ___ ___  __  __ ___ ___ _      _ _____ ___ ___  _  _
	 *   / __/ _ \|  \/  | _ \_ _| |    /_\_   _|_ _/ _ \| \| |
	 *  | (_| (_) | |\/| |  _/| || |__ / _ \| |  | | (_) | .` |
	 *   \___\___/|_|  |_|_| |___|____/_/ \_\_| |___\___/|_|\_|
	 */
	MsgParseInvalidEmptyCharacter =
		"char cannot be empty"
	MsgParseInvalidCharacter =
		"char should only be 1 character"

	MsgParseReserveValueIsNotConst =
		"%s is not a const"
	MsgParseReserveOverrideNotAllowed =
		"memory %s already exists"
	MsgParseReserveMissingWord =
		"invalid or missing word\n" +
			"\t\treserve mem 1024 .\n" +
			"\t\t        ^^^"
	MsgParseReserveMissingValue =
		"invalid or missing value\n" +
			"\t\treserve mem 1024 .\n" +
			"\t\t            ^^^^"
	MsgParseReserveMissingDot =
		"missing '.'\n" +
			"\t\treserve mem 1024 .\n" +
			"\t\t                 ^"

	MsgParseBindAlreadyBound =
		"function has bindings already"
	MsgParseBindEmptyBody =
		"missing or invalid bind content\n" +
			"\t\tbind a b c .\n" +
			"\t\t     ^^^^^"
	MsgParseBindMissingCloseStmt =
		"missing ')'\n" +
			"\t\tbind ( a b c )\n" +
			"\t\t             ^"
	MsgParseBindMissingOpenStmt =
		"missing '('\n" +
			"\t\tbind ( a b c )\n" +
			"\t\t     ^"

	MsgParseDoOrphanTokenFound =
		"only use 'do' when starting a block statement\nE.g.:\n\tif [condition] do [...] else [...] .\n\t^^             ^^\n'do' can be used in other blocks like function and loops"

	MsgParseElseOrphanTokenFound =
		"only use 'else' after starting an 'if' statement\nE.g.:\n\tif [condition] do [...] else [...] .\n\t^^                      ^^^^"

	MsgParseDotOrphanTokenFound =
		"'.' must have an associated block\n" +
			"E.g.:\n" +
			"\t\tif [condition] do [...] else [...] .\n" +
			"\t\t^^                                 ^\n"

	MsgParseCallMainFunctionMissing =
		"entry point is not defined\n" +
			"define a 'main' function"


	MsgParseWordNotFound = "undefined word %s"

	MsgParseErrorProgramScope =
		"cannot do this in global scope"

	MsgParseFunctionMissingName =
		"invalid or missing function name\n" +
			"\t\tfunction my-func do [...] .\n" +
			"\t\t         ^^^^^^^"
	MsgParseFunctionUnknownType =
		"type '%s' is unknown"
	MsgParseFunctionNoReturnSpecified =
		"no return values specified after '->'\n" +
			"\t\tfunction my-func -> do [...] .\n" +
			"\t\t                 ^^"
	MsgParseFunctionMissingDo =
		"missing 'do' keyword\n" +
			"\t\tfunction my-func do [...] .\n" +
			"\t\t                 ^^"
	MsgParseFunctionMissingDot =
		"missing '.'\n" +
			"\t\tfunction my-func do [...] .\n" +
			"\t\t                          ^"
	MsgParseFunctionMainAlreadyDefined =
		"function main already defined at %s:%d"
	MsgParseFunctionNotPolymorphic =
		"function %s is not polymorphic and has a non-polymorphic variant"

	MsgParseConstMissingWord =
		"invalid or missing word\n" +
			"\t\tconst my-const [...] .\n" +
			"\t\t      ^^^^^^^^"
	MsgParseConstMissingContent =
		"const cannot be empty\n" +
			"\t\tconst my-const [...] .\n" +
			"\t\t               ^^^^^"
	MsgParseConstInvalidContent =
		"const %s can only have int or simple arithmetic operations (+ or *)\n" +
			"\t\tconst my-const 32 1024 * .\n" +
			"\t\t               ^^^^^^^^^"
	MsgParseConstMissingDot =
		"missing '.'\n" +
			"\t\tconst my-const [...] .\n" +
			"\t\t                     ^"
	MsgParseConstOverrideNotAllowed =
		"const %s already exists\n"


	/*   _______   _____ ___ ___ _  _ ___ ___ _  __
	 *  |_   _\ \ / / _ \ __/ __| || | __/ __| |/ /
	 *    | |  \ V /|  _/ _| (__| __ | _| (__| ' <
	 *    |_|   |_| |_| |___\___|_||_|___\___|_|\_\
	 */
	MsgTypecheckMainFunctionNoArgumentsOrReturn =
		"function 'main' must have no arguments and no return values"
	MsgTypecheckFunctionPolymorphicMatchNotFound =
		"no polymorphic function '%s' with matching parameters\n" +
			"\t\thave (%s)\n" +
			"\t\twant %s"
	MsgTypecheckArgumentsTypeMismatch =
		"incorrect arguments to call %s\n" +
			"\t\thave (%s)\n" +
			"\t\twant (%s)"
	MsgTypecheckArgumentsTypesMismatch =
		"incorrect arguments to call %s\n" +
			"\t\thave (%s)\n" +
			"\t\twant %s"
	MsgTypecheckNotExplicitlyReturned =
		"unhandled stack values\n" +
			"\t\tfunction '%s'\n" +
			"\t\t(%s)"
	MsgTypecheckMissingEntryPoint =
		"function 'main' is undeclared"
	MsgTypecheckWarningNotCalled =
		"Warning: function '%s' declared but not in use\n"

	MsgsTypecheckStackSizeChangedAfterBlock =
		"stack size cannot change after block statement"
	MsgsTypecheckStackTypeChangedAfterBlock =
		"stack types cannot change after block statement"
)
