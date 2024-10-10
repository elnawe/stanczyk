package skc

import (
	"fmt"
	"reflect"
	"slices"
)

type Parser struct {
	globalWords   []string
	bodyStack     []Token
	currentFn     *Function

	previousToken Token
	currentToken  Token
	tokens        []Token
	internal      bool
	index         int
}

type Stack struct {
	bodyStack    []Token
	currentScope int
	scopeToken   [32]Token
	snapshots    [32][]Value
	values       []Value
}

type ScopeKind int

const (
	SCOPE_BIND ScopeKind = iota
	SCOPE_LOOP
	SCOPE_IF
	SCOPE_ELSE
)

func (this *Stack) push(value Value) {
	this.values = append(this.values, value)
}

func (this *Stack) pop() Value {
	lastIndex := len(this.values)-1
	result := this.values[lastIndex]
	this.values = slices.Clone(this.values[:lastIndex])
	return result
}

func (this *Stack) popSnapshot() {
	this.snapshots[this.currentScope] = make([]Value, 0, 0)
	this.currentScope--
}

func (this *Stack) pushSnapshot() {
	this.currentScope++
	this.snapshots[this.currentScope] = slices.Clone(this.values)
}

func (this *Stack) validateSnapshot() {
	currentSnapshotValues := this.snapshots[this.currentScope]

	if len(currentSnapshotValues) != len(this.values) {
		addError(CompilerError{
			code: CodeValidationError,
			message: StackChangedInCodeBlock,
			token: this.scopeToken[this.currentScope],
		})
	} else {
		for i, t := range currentSnapshotValues {
			if this.values[i] != t {
				addError(CompilerError{
					code: CodeValidationError,
					message: StackChangedInCodeBlock,
					token: this.scopeToken[this.currentScope],
				})
				break
			}
		}
	}
}

func (this *Stack) reset() {
	this.currentScope = 0
	this.values = make([]Value, 0, 0)
}

// CODE STARTS HERE

var file   FileManager
var parser Parser
var stack  Stack

func addError(error CompilerError, args ...any) {
	if parser.currentFn != nil {
		parser.currentFn.error = true
	}

	error.message = fmt.Sprintf(error.message, args...)
	TheProgram.errors = append(TheProgram.errors, error)
}

func startParser(f File) {
	parser.index = 0
	parser.tokens = TokenizeFile(f.filename, f.source)
	parser.currentToken = parser.tokens[parser.index]
	parser.internal = f.internal
}

func advance() {
	parser.index++
	parser.previousToken = parser.currentToken
	parser.currentToken  = parser.tokens[parser.index]
}

func check(kind TokenType) bool {
	return kind == parser.currentToken.kind
}

func consume(kind TokenType, err string, args ...any) {
	if kind == parser.currentToken.kind {
		advance()
		return
	}

	ReportErrorAtLocation(err, parser.previousToken.loc, args...)
	ExitWithError(GlobalParseError)
}

func isParsingFunction() bool {
	return parser.currentFn != nil
}

func match(kind TokenType) bool {
	if !check(kind) {
		return false
	}
	advance()
	return true
}

func bind(nw []string) int {
	bindings := &parser.currentFn.bindings
	count := len(nw)
	bindings.count = append([]int{count}, bindings.count...)
	bindings.words = append(nw, bindings.words...)
	return count
}

func unbind() int {
	bindings := &parser.currentFn.bindings
	unbindAmount := bindings.count[0]
	bindings.count = bindings.count[1:]
	bindings.words = bindings.words[unbindAmount:]
	return unbindAmount
}

func openScope(s ScopeKind, t Token) *Scope {
	newScope := Scope{
		ipStart: len(parser.currentFn.code),
		tokenStart: t,
		kind: s,
	}
	parser.currentFn.scope = append(parser.currentFn.scope, newScope)
	lastScopeIndex := len(parser.currentFn.scope)-1
	stack.pushSnapshot()
	return &parser.currentFn.scope[lastScopeIndex]
}

func getCurrentScope() *Scope {
	lastScopeIndex := len(parser.currentFn.scope)-1
	return &parser.currentFn.scope[lastScopeIndex]
}

func getCountForScopeKind(s ScopeKind) int {
	var count int
	for _, ss := range parser.currentFn.scope {
		if ss.kind == s {
			count++
		}
	}
	return count
}

func closeScopeAfterCheck(s ScopeKind) {
	lastScopeIndex := len(parser.currentFn.scope)-1
	lastOpenedScope := parser.currentFn.scope[lastScopeIndex]

	if lastOpenedScope.kind == s {
		parser.currentFn.scope = parser.currentFn.scope[:lastScopeIndex]

		// TODO: This should live in a configuration per scope function
		// something like: getConfiguration(SCOPE_BIND)
		// and it will tell me if I need to validate scope or not.
		// Actually this might not be even needed, if we make the let binding
		// be an actual concatenative expression.
		if s != SCOPE_BIND {
			stack.validateSnapshot()
		}

		stack.popSnapshot()
	} else {
		addError(CompilerError{
			code: CodeParseError,
			message: IncorrectBlockOfCodeClosingStatement,
			token: lastOpenedScope.tokenStart,
		})
	}
}

func getLimitIndexBindWord() (string, string) {
	loopIndexByte := 72
	loopScopeDepth := getCountForScopeKind(SCOPE_LOOP)
	loopIndexByte += loopScopeDepth
	loopIndexWord := string(byte(loopIndexByte))
	limitWord := loopIndexWord + "limit"
	return limitWord, loopIndexWord
}

func emit(code Code) {
	parser.currentFn.WriteCode(code)
}

func emitConstant() bool {
	var found bool
	var result Constant
	t := parser.previousToken
	word := t.value.(string)

	if isParsingFunction() {
		for _, c := range parser.currentFn.constants {
			if c.word == word {
				found = true
				result = c
				break
			}
		}
	}

	if !found {
		for _, c := range TheProgram.constants {
			if c.word == word {
				found = true
				result = c
				break
			}
		}
	}

	if found {
		code := Code{loc: t.loc, value: result.value.variant}

		switch result.value.kind {
		case BOOLEAN:
			code.op = OP_PUSH_BOOL
		case BYTE:
			code.op = OP_PUSH_CHAR
		case INT64:
			code.op = OP_PUSH_INT
		case STRING:
			code.op = OP_PUSH_STR
		}

		emitValue(result.value)
		emit(code)
	}

	return found
}

func emitReturn() {
	emit(Code{
		op: OP_RET,
		loc: parser.previousToken.loc,
	})
}

func emitValue(v Value) {
	// TODO: Reenable this once things are moved to this file
	// stack.push(v)
	// emit(Code{
	// 	op: OP_PUSH_VALUE,
	// 	loc: v.token.loc,
	// 	value: v,
	// })
}

func isWordInUse(t Token) bool {
	test := t.value.(string)

	if isParsingFunction() {
		// TODO: Implement the checks here, these are different from
		// the global ones because it needs to check for the word being
		// used in local scope and disregard globals, except for Functions
	} else {
		for _, word := range parser.globalWords {
			if word == test {
				return true
			}
		}
	}

	return false
}

func createConstant() Constant {
	var newConst Constant

	if !match(TOKEN_WORD) {
		t := parser.previousToken

		if isParsingFunction() {
			parser.currentFn.error = true
			addError(CompilerError{
				code: FunctionParseError,
				message: DeclarationWordMissing,
				token: t,
			})
		} else {
			ReportErrorAtLocation(DeclarationWordMissing, t.loc)
			ExitWithError(GlobalParseError)
		}
	}

	wordT := parser.previousToken
	newConst.word = wordT.value.(string)

	if isWordInUse(wordT) {
		if isParsingFunction() {
			parser.currentFn.error = true
			addError(CompilerError{
				code: FunctionParseError,
				message: DeclarationWordAlreadyUsed,
				token: wordT,
			}, newConst.word)
		} else {
			ReportErrorAtLocation(
				DeclarationWordAlreadyUsed,
				wordT.loc,
				newConst.word,
			)
			ExitWithError(GlobalParseError)
		}
	}

	advance()
	valueT := parser.previousToken
	newConst.value.token = valueT

	switch valueT.kind {
	case TOKEN_CONSTANT_CHAR:
		newConst.value.kind = BYTE
		newConst.value.variant = valueT.value
	case TOKEN_CONSTANT_FALSE:
		newConst.value.kind = BOOLEAN
		newConst.value.variant = 0
	case TOKEN_CONSTANT_INT:
		newConst.value.kind = INT64
		newConst.value.variant = valueT.value
	case TOKEN_CONSTANT_STR:
		newConst.value.kind = STRING
		newConst.value.variant = valueT.value
	case TOKEN_CONSTANT_TRUE:
		newConst.value.kind = BOOLEAN
		newConst.value.variant = 1
	default:
		if isParsingFunction() {
			parser.currentFn.error = true
			addError(CompilerError{
				code: FunctionParseError,
				message: ConstantValueKindNotAllowed,
				token: valueT,
			})
		} else {
			ReportErrorAtLocation(ConstantValueKindNotAllowed, valueT.loc)
			ExitWithError(GlobalParseError)
		}
	}

	if !isParsingFunction() {
		parser.globalWords = append(parser.globalWords, newConst.word)
	}

	return newConst
}

func createVariable(currentOffset int) (Variable, int) {
	var newVar Variable
	var newOffset int
	const SIZE_64b = 8

	if !match(TOKEN_WORD) {
		t := parser.previousToken
		if isParsingFunction() {
			parser.currentFn.error = true
			addError(CompilerError{
				code: FunctionParseError,
				message: DeclarationWordMissing,
				token: t,
			})
		} else {
			ReportErrorAtLocation(DeclarationWordMissing, t.loc)
			ExitWithError(GlobalParseError)
		}
	}

	wordT := parser.previousToken
	newVar.word = wordT.value.(string)
	newVar.offset = currentOffset
	// TODO: This should be calculated, not hardcoded. It should take the size
	// of the type (next token) and align it to 8 bytes
	// formula: size + 7 / 8 * 8
	newOffset = currentOffset + SIZE_64b

	if isWordInUse(wordT) {
		if isParsingFunction() {
			parser.currentFn.error = true
			addError(CompilerError{
				code: FunctionParseError,
				message: DeclarationWordAlreadyUsed,
				token: wordT,
			}, newVar.word)
		} else {
			ReportErrorAtLocation(
				DeclarationWordAlreadyUsed,
				wordT.loc,
				newVar.word,
			)
			ExitWithError(GlobalParseError)
		}
	}

	advance()
	valueT := parser.previousToken

	switch valueT.kind {
	case TOKEN_BOOL: newVar.kind = DATA_BOOL
	case TOKEN_CHAR: newVar.kind = DATA_CHAR
	case TOKEN_INT:  newVar.kind = DATA_INT
	case TOKEN_PTR:  newVar.kind = DATA_PTR
	case TOKEN_STR:  newVar.kind = DATA_STR
	default:
		if isParsingFunction() {
			parser.currentFn.error = true
			addError(CompilerError{
				code: FunctionParseError,
				message: VariableValueKindNotAllowed,
				token: valueT,
			})
		} else {
			ReportErrorAtLocation(VariableValueKindNotAllowed, valueT.loc)
			ExitWithError(GlobalParseError)
		}
	}

	if !isParsingFunction() {
		parser.globalWords = append(parser.globalWords, newVar.word)
	}

	return newVar, newOffset
}

func expandWordMeaning() {
	t := parser.previousToken

	b, bfound := getBind(t)

	if bfound {
		emit(b)
		return
	}

	v, vfound := getVariable(t)
	if vfound {
		emit(v)
		return
	}

	code_f, ok_f := getFunction(t)
	if ok_f {
		emit(code_f)
		return
	}

	if !emitConstant() {
		// If nothing has been found, emit the error.
		msg := fmt.Sprintf(MsgParseWordNotFound, t.value.(string))
		ReportErrorAtLocation(msg, t.loc)
		ExitWithError(CodeCodegenError)
	}
}

func setCurrentFunctionToParse(t Token) {
	test := t.value.(string)

	for i, fn := range TheProgram.chunks {
		if fn.word == test && !fn.parsed {
			parser.currentFn = &TheProgram.chunks[i]
			return
		}
	}

	ReportErrorAtLocation(FunctionDeclarationNotFound, t.loc, test)
	ExitWithError(GlobalParseError)
}

func validateFunction(test Function) {
	var other []Function

	for _, fn := range TheProgram.chunks {
		if fn.word == test.word {
			other = append(other, fn)
		}
	}

	if test.word == "main" {
		if len(other) > 0 {
			ReportErrorAtLocation(MainFunctionRedefined, test.loc)
			ExitWithError(GlobalParseError)
		}

		if len(test.arguments.types) > 0 || len(test.returns.types) > 0 {
			ReportErrorAtLocation(MainFunctionInvalidSignature, test.loc)
			ExitWithError(GlobalParseError)
		}
	}

	for _, fn := range other {
		if reflect.DeepEqual(fn.arguments, test.arguments) {
			ReportErrorAtLocation(
				FunctionSignatureAlreadyExists, test.loc,
				test.word, fn.loc.f, fn.loc.l, fn.loc.c,
			)
			ExitWithError(GlobalParseError)
		}

		if !reflect.DeepEqual(fn.returns, test.returns) {
			ReportErrorAtLocation(
				FunctionSignatureDifferentReturns, test.loc,
				test.word, fn.loc.f, fn.loc.l, fn.loc.c,
			)
			ExitWithError(GlobalParseError)
		}
	}
}

func parseTokens() {
	t := parser.previousToken

	switch t.kind {
	case TOKEN_CONSTANT_CHAR:

	}
}

func Compile() {
	// Required Runtime Library
	file.Open("runtime")

	// User entry file(s)
	file.Open(Stanczyk.workspace.entry)

	// Compilation:
	//   Step 1: Register globals (const, var, fn)
	for i := 0; i < len(file.files); i++ {
		f := file.files[i]
		startParser(f)

		for !check(TOKEN_EOF) {
			advance()
			t := parser.previousToken

			switch t.kind {
			case TOKEN_CONST:
				newConst := createConstant()
				TheProgram.constants = append(TheProgram.constants, newConst)
			case TOKEN_FN:
				var function Function

				function.internal = parser.internal
				function.ip = len(TheProgram.chunks)
				function.loc = t.loc
				function.parsed = false

				if !match(TOKEN_WORD) {
					// If a word is not found after the function keyword we
					// cannot recover. We will need to exit
					ReportErrorAtLocation(DeclarationWordMissing, t.loc)
					ExitWithError(GlobalParseError)
				}

				word := parser.previousToken.value.(string)
				function.name = word
				function.word = word
				consume(TOKEN_PAREN_OPEN, UnexpectedSymbol, "(")

				parsingArguments := true

				if !check(TOKEN_PAREN_CLOSE) && !check(TOKEN_EOF) {
					var param Argument
					advance()
					t := parser.previousToken

					switch t.kind {
					case TOKEN_DASH_DASH_DASH:
						parsingArguments = false
					case TOKEN_ANY:
						if !parser.internal {
							ReportErrorAtLocation(
								ParameterAnyOnNonInternalFunction, t.loc,
							)
							ExitWithError(GlobalParseError)
						}

						param.typ = DATA_ANY
						param.kind = ANY
					case TOKEN_BOOL:
						param.typ = DATA_BOOL
						param.kind = BOOLEAN
					case TOKEN_CHAR:
						param.typ = DATA_CHAR
						param.kind = BYTE
					case TOKEN_INT:
						param.typ = DATA_INT
						param.kind = INT64
					case TOKEN_PTR:
						param.typ = DATA_PTR
						param.kind = POINTER
					case TOKEN_STR:
						param.typ = DATA_STR
						param.kind = STRING
					case TOKEN_PARAPOLY:
						paramWord := t.value.(string)

						if !parsingArguments {
							ReportErrorAtLocation(
								ParameterVariadicOnlyInArguments, t.loc,
								paramWord, paramWord[1:],
							)
							ExitWithError(GlobalParseError)
						}

						function.arguments.variadic = true
						param.kind = VARIADIC
						param.name = paramWord
						param.typ = DATA_INFER
					case TOKEN_WORD:
						word := t.value.(string)

						if parsingArguments {
							ReportErrorAtLocation(
								// TODO: I should allow this once custom types are implemented.
								"TODO: not implemented",
								t.loc,
							)
							ExitWithError(GlobalParseError)
						}

						funcArgs := function.arguments
						argTest := Argument{kind: VARIADIC, name: word, typ: DATA_INFER}

						if funcArgs.variadic && Contains(funcArgs.types, argTest) {
							param.kind = VARIADIC
							param.name = word
							function.returns.variadic = true
						} else {
							ReportErrorAtLocation(ParameterVariadicNotFound, t.loc, word)
							ExitWithError(GlobalParseError)
						}
					default:
						ReportErrorAtLocation(ParameterTypeUnknown, t.loc)
						ExitWithError(GlobalParseError)
					}

					if parsingArguments {
						function.arguments.types = append(function.arguments.types, param)
					} else {
						function.returns.types = append(function.returns.types, param)
					}
				}

				consume(TOKEN_PAREN_CLOSE, UnexpectedSymbol, ")")
				validateFunction(function)
				for !check(TOKEN_RET) && !check(TOKEN_EOF) { advance() }
				consume(TOKEN_RET, UnexpectedSymbol, "ret")

				if !isParsingFunction() {
					parser.globalWords = append(parser.globalWords, function.word)
				}

				TheProgram.chunks = append(TheProgram.chunks, function)
			case TOKEN_USING:
				advance()
				wordT := parser.previousToken

				if wordT.kind != TOKEN_WORD {
					addError(CompilerError{
						code: UsingError,
						message: WordMissingAfterUsing,
						token: t,
					})
					continue
				}
				file.Open(wordT.value.(string))
			case TOKEN_VAR:
				newVar, newOffset := createVariable(TheProgram.staticMemorySize)
				TheProgram.variables = append(TheProgram.variables, newVar)
				TheProgram.staticMemorySize = newOffset
			default:
				// Handle errors for non-global allowed tokens.
				// These kind of errors are usually non-recoverable, this is
				// because the parsing will be corrupt, at least for this file.
				ReportErrorAtLocation(NonDeclarationInGlobalScope, t.loc)
				ExitWithError(CriticalError)
			}
		}
	}

	//   Step 2: Compile function contents
	for i := 0; i < len(file.files); i++ {
		f := file.files[i]
		startParser(f)

		for !check(TOKEN_EOF) {
			advance()
			t := parser.previousToken

			switch t.kind {
			case TOKEN_FN:
				advance()
				wordT := parser.previousToken
				setCurrentFunctionToParse(wordT)

				for !match(TOKEN_PAREN_CLOSE) { advance() }

				for !check(TOKEN_RET) && !check(TOKEN_EOF) {
					advance()
					parseTokens()
				}

				consume(TOKEN_RET, UnexpectedSymbol, "ret")
				parser.currentFn.parsed = true
				emitReturn()
			default:
				ReportErrorAtLocation(NonDeclarationInGlobalScope, t.loc)
				ExitWithError(CriticalError)
			}
		}
	}

	if len(TheProgram.errors) > 0 {
		for _, e := range TheProgram.errors {
			ReportErrorAtLocation(e.message, e.token.loc)
		}
		ExitWithError(CompilationError)
	}
}
