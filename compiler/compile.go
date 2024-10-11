package skc

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
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
	binds        []ValueKind
	bodyStack    []Token
	currentScope int
	scopeToken   [32]Token
	snapshots    [32][]ValueKind
	values       []ValueKind
	variadicMap  map[string]ValueKind
}

type ScopeKind int

const (
	SCOPE_LOOP ScopeKind = iota
	SCOPE_IF
	SCOPE_ELSE
)

func (this *Stack) castTo(v ValueKind) {
	this.pop()
	// TODO: Add casting validations
	this.push(v)
}

func (this *Stack) pop() ValueKind {
	if len(this.values) == 0 {
		ReportErrorAtLocation(StackUnderflow, parser.previousToken.loc)
		ExitWithError(CriticalError)
	}

	lastIndex := len(this.values)-1
	result := this.values[lastIndex]
	this.values = slices.Clone(this.values[:lastIndex])
	return result
}

func (this *Stack) push(v ValueKind) {
	this.values = append(this.values, v)
}

func (this *Stack) popSnapshot() {
	this.snapshots[this.currentScope] = make([]ValueKind, 0, 0)
	this.currentScope--
}

func (this *Stack) pushSnapshot() {
	this.currentScope++
	this.snapshots[this.currentScope] = slices.Clone(this.values)
}

func (this *Stack) reset() {
	this.currentScope = 0
	this.binds  = make([]ValueKind, 0, 0)
	this.values = make([]ValueKind, 0, 0)
	this.variadicMap = make(map[string]ValueKind, 0)
}

func (this *Stack) setup() {
	for _, t := range parser.currentFn.arguments.types {
		this.push(t.kind)
	}
}

func (this *Stack) validate() {
	expectedReturnCount := len(parser.currentFn.returns.types)

	if len(this.values) != expectedReturnCount {
		addError(CompilerError{
			code: FunctionParseError,
			message: IncorrectValuesAtReturn,
			token: Token{loc: parser.currentFn.loc},
		}, parser.currentFn.word, len(this.values), expectedReturnCount)
	}

	for i, t := range parser.currentFn.returns.types {
		skv := this.values[i]

		if skv != t.kind {
			addError(CompilerError{
				code: FunctionParseError,
				message: IncorrectValueTypeAtReturn,
				token: Token{loc: parser.currentFn.loc},
			}, parser.currentFn.word, skv, t.kind)
		}
	}

	this.reset()
}

func (this *Stack) validateSnapshot() {
	currentSnapshotValues := this.snapshots[this.currentScope]
	c := getCurrentScope()

	if len(currentSnapshotValues) != len(this.values) {
		addError(CompilerError{
			code: CodeValidationError,
			message: StackChangedInCodeBlock,
			token: c.tokenStart,
		})
	} else {
		for i, t := range currentSnapshotValues {
			if this.values[i] != t {
				addError(CompilerError{
					code: CodeValidationError,
					message: StackChangedInCodeBlock,
					token: c.tokenStart,
				})
				break
			}
		}
	}
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

func takeFromFunctionCode(quant int) []Code {
	var result []Code
	codeLength := len(parser.currentFn.code)

	for index := codeLength-quant; index < codeLength; index++ {
		result = append(result, parser.currentFn.code[index])
	}

	parser.currentFn.code = parser.currentFn.code[:codeLength-quant]
	return result
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
		stack.validateSnapshot()
		stack.popSnapshot()
		parser.currentFn.scope = parser.currentFn.scope[:lastScopeIndex]
	} else {
		addError(CompilerError{
			code: CodeParseError,
			message: IncorrectBlockOfCodeClosingStatement,
			token: lastOpenedScope.tokenStart,
		})
	}
}

func getLimitIndexBindWords() (string, string) {
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

func emitPushLet(word string) bool {
	t := parser.previousToken
	b, found := getBind(word)

	if found {
		stack.push(stack.binds[b])
		emit(Code{op: OP_PUSH_LET, loc: t.loc, value: b})
	}

	// Should add value to the stack
	stack.push(RAWPOINTER)

	return found
}

func emitConstant(word string) bool {
	c, found := getConstant(word)

	if found {
		emitValue(c.value)
	}

	return found
}

func emitFunctionCall(word string) bool {
	t := parser.previousToken
	funcIPs, _ := getFunctions(word)
	result := -1

	if len(funcIPs) == 1 {
		result = funcIPs[0]
	} else {
		for _, ip := range funcIPs {
			var paramsFromFn []ValueKind
			f := TheProgram.chunks[ip]
			firstIndex := len(stack.values) - len(f.arguments.types)
			reversedStack := stack.values[firstIndex:]
			stackValuesReduced := reversedStack[:len(f.arguments.types)]

			for _, k := range f.arguments.types {
				paramsFromFn = append(paramsFromFn, k.kind)
			}

			if reflect.DeepEqual(paramsFromFn, stackValuesReduced) {
				result = ip
				break
			}
		}
	}

	if result == -1 {
		return false
	}

	funcRef := TheProgram.chunks[result]

	emit(Code{op: OP_FUNCTION_CALL, loc: t.loc, value: result})

	if funcRef.arguments.variadic {
		stack.variadicMap = make(map[string]ValueKind)
		firstIndex := len(stack.values) - len(funcRef.arguments.types)
		reversedStack := stack.values[firstIndex:]

		for i, t := range funcRef.arguments.types {
			if t.kind == VARIADIC {
				if stack.variadicMap[t.name] == UNKNOWN {
					stack.variadicMap[t.name] = reversedStack[i]
				}
			}
		}
	}

	for range funcRef.arguments.types {
		stack.pop()
	}

	for _, t := range funcRef.returns.types {
		if t.kind == VARIADIC {
			stack.push(stack.variadicMap[t.name])
		} else {
			stack.push(t.kind)
		}
	}

	return true
}

func emitLetBind(words ...string) {
	for range words {
		stack.binds = append([]ValueKind{stack.pop()}, stack.binds...)
	}

	emit(Code{op: OP_LET_BIND, loc: parser.previousToken.loc, value: bind(words)})
}

func emitLetUnbind() {
	amount := unbind()
	stack.binds = stack.binds[amount:]
	emit(Code{op: OP_LET_UNBIND, loc: parser.previousToken.loc, value: amount})
}

func emitReturn() {
	emit(Code{
		op: OP_RET,
		loc: parser.previousToken.loc,
	})
}

func emitValue(v Value) {
	loc := v.token.loc

	stack.push(v.kind)
	switch v.kind {
	case BOOLEAN: emit(Code{op: OP_PUSH_BOOL, loc: loc, value: v.variant})
	case BYTE: emit(Code{op: OP_PUSH_CHAR, loc: loc, value: v.variant})
	case INT64: emit(Code{op: OP_PUSH_INT, loc: loc, value: v.variant})
	case STRING: emit(Code{op: OP_PUSH_STR, loc: loc, value: v.variant})
	}
}

func emitVariable(word string) bool {
	t := parser.previousToken
	v, found := getVariable(word)

	if found {
		switch v.address {
		case GLOBAL_VARIABLE:
			emit(Code{op: OP_PUSH_GLOBAL_VARIABLE, loc: t.loc, value: v.offset})
		case LOCAL_VARIABLE:
			emit(Code{op: OP_PUSH_LOCAL_VARIABLE, loc: t.loc, value: v.offset})
		}

		stack.push(v.kind)
	}

	return found
}

func getBind(word string) (int, bool) {
	for i, b := range parser.currentFn.bindings.words {
		if b == word {
			return i, true
		}
	}

	return -1, false
}

func getConstant(word string) (Constant, bool) {
	if isParsingFunction() {
		for _, c := range parser.currentFn.constants {
			if c.word == word {
				return c, true
			}
		}
	}

	for _, c := range TheProgram.constants {
		if c.word == word {
			return c, true
		}
	}

	return Constant{}, false
}

func getFunctions(word string) ([]int, bool) {
	var results []int

	for i, f := range TheProgram.chunks {
		if f.word == word {
			results = append(results, i)
		}
	}

	return results, len(results) > 0
}

func getVariable(word string) (Variable, bool) {
	if isParsingFunction() {
		for _, v := range parser.currentFn.variables {
			if v.word == word {
				return v, true
			}
		}
	}

	for _, v := range TheProgram.variables {
		if v.word == word {
			return v, true
		}
	}

	return Variable{}, false
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

func createConstant() {
	var newConst Constant

	if !match(TOKEN_WORD) {
		t := parser.previousToken

		if isParsingFunction() {
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

	if isParsingFunction() {
		parser.currentFn.constants = append(parser.currentFn.constants, newConst)
	} else {
		parser.globalWords = append(parser.globalWords, newConst.word)
		TheProgram.constants = append(TheProgram.constants, newConst)
	}
}

func createFunction() {
	var function Function
	t := parser.previousToken

	function.internal = parser.internal
	function.ip = len(TheProgram.chunks)
	function.loc = t.loc
	function.parsed = false
	// TODO: Mark function as called after they are actually called
	function.called = true

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

	for !check(TOKEN_PAREN_CLOSE) && !check(TOKEN_EOF) {
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

			param.kind = ANY
		case TOKEN_BOOL:
			param.kind = BOOLEAN
		case TOKEN_CHAR:
			param.kind = BYTE
		case TOKEN_INT:
			param.kind = INT64
		case TOKEN_PTR:
			param.kind = RAWPOINTER
		case TOKEN_STR:
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
			argTest := Argument{kind: VARIADIC, name: word}

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
			function.arguments.types =
				append(function.arguments.types, param)
		} else {
			function.returns.types =
				append(function.returns.types, param)
		}
	}

	consume(TOKEN_PAREN_CLOSE, UnexpectedSymbol, ")")
	validateFunction(function)
	for !check(TOKEN_RET) && !check(TOKEN_EOF) { advance() }
	consume(TOKEN_RET, UnexpectedSymbol, "ret")

	parser.globalWords =
		append(parser.globalWords, function.word)
	TheProgram.chunks =
		append(TheProgram.chunks, function)
}

func createVariable() {
	var newVar Variable
	var currentOffset int
	var newOffset int
	const SIZE_64b = 8

	if isParsingFunction() {
		currentOffset = parser.currentFn.localMemorySize
	} else {
		currentOffset = TheProgram.staticMemorySize
	}

	if !match(TOKEN_WORD) {
		t := parser.previousToken
		if isParsingFunction() {
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
	case TOKEN_BOOL:
		newVar.kind = BOOLEAN
	case TOKEN_CHAR:
		newVar.kind = BYTE
	case TOKEN_INT:
		newVar.kind = INT64
	case TOKEN_PTR:
		newVar.kind = RAWPOINTER
	case TOKEN_STR:
		newVar.kind = STRING
	default:
		if isParsingFunction() {
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

	if isParsingFunction() {
		parser.currentFn.variables = append(parser.currentFn.variables, newVar)
		parser.currentFn.localMemorySize = newOffset
	} else {
		parser.globalWords = append(parser.globalWords, newVar.word)
		TheProgram.variables = append(TheProgram.variables, newVar)
		TheProgram.staticMemorySize = newOffset
	}
}

func expandWordMeaning() {
	t := parser.previousToken
	word := t.value.(string)

	if !(emitFunctionCall(word) ||
		emitPushLet(word) ||
		emitConstant(word) ||
		emitVariable(word)) {
		if isParsingFunction() {
			addError(CompilerError{
				code: FunctionParseError,
				message: UnknownWord,
				token: t,
			}, t.value.(string))
		} else {
			ReportErrorAtLocation(UnknownWord, t.loc, t.value.(string))
			ExitWithError(GlobalParseError)
		}
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
	// CONSTANTS
	case TOKEN_CONSTANT_CHAR:
		emitValue(Value{kind: BYTE, token: t, variant: t.value.(uint8)})
	case TOKEN_CONSTANT_FALSE:
		emitValue(Value{kind: BOOLEAN, token: t, variant: 0})
	case TOKEN_CONSTANT_INT:
		emitValue(Value{kind: INT64, token: t, variant: t.value.(int)})
	case TOKEN_CONSTANT_STR:
		emitValue(Value{kind: STRING, token: t, variant: t.value.(string)})
	case TOKEN_CONSTANT_TRUE:
		emitValue(Value{kind: BOOLEAN, token: t, variant: 1})
	case TOKEN_AMPERSAND:
		var pointerData ValuePointer
		word := t.value.(string)
		b, bfound := getBind(word)
		v, vfound := getVariable(word)

		if vfound {
			pointerData.address = v.address
			pointerData.offset = v.offset
		} else if bfound {
			pointerData.address = BINDING
			pointerData.offset = b
		} else {
			addError(CompilerError{
				code: FunctionParseError,
				message: UnknownWord,
				token: t,
			}, t.value.(string))
		}

		emitValue(Value{kind: RAWPOINTER, token: t, variant: pointerData})

	// TYPE CASTING
	case TOKEN_BOOL:
		stack.castTo(BOOLEAN)
	case TOKEN_CHAR:
		stack.castTo(BYTE)
	case TOKEN_INT:
		stack.castTo(INT64)
	case TOKEN_PTR:
		stack.castTo(RAWPOINTER)
	case TOKEN_STR:
		stack.castTo(STRING)

	// DEFINITION
	case TOKEN_CONST:
		createConstant()
	case TOKEN_CURLY_BRACKET_OPEN:
		var tokens []Token

		if len(stack.bodyStack) > 0 {
			addError(CompilerError{
				code: FunctionParseError,
				message: BodyStackIsAlreadyTaken,
				token: t,
			})
			for !match(TOKEN_CURLY_BRACKET_CLOSE) { advance() }
		}

		for !check(TOKEN_CURLY_BRACKET_CLOSE) && !check(TOKEN_EOF) {
			advance()
			tokens = append(tokens, parser.previousToken)
		}

		if len(tokens) == 0 {
			addError(CompilerError{
				code: FunctionParseError,
				message: BodyDefinitionEmpty,
				token: t,
			})
		}

		consume(TOKEN_CURLY_BRACKET_CLOSE, UnexpectedSymbol, "}")
		stack.bodyStack = tokens
	case TOKEN_LET:
		var newWords []string

		for match(TOKEN_WORD) {
			word := parser.previousToken.value.(string)
			newWords = append(newWords, word)
		}

		consume(TOKEN_BANG, UnexpectedSymbol, "!")
		emitLetBind(newWords...)
	case TOKEN_VAR:
		createVariable()

	// INTRINSICS
	case TOKEN_ARGC:
		emit(Code{op: OP_ARGC, loc: t.loc})
	case TOKEN_ARGV:
		emit(Code{op: OP_ARGV, loc: t.loc})
	case TOKEN_ASM:
		// Note: This is a special instrinsic macro that uses the @body and
		// calculates the stack modifications necessary to make sure the
		// function signature is respected.
		var popCount int
		var pushCount int
		var line []string
		var value ASMValue
		body := stack.bodyStack
		stack.bodyStack = make([]Token, 0, 0)

		for i, t := range body {
			switch t.kind {
			case TOKEN_BRACKET_CLOSE:
				line = append(line, "]")
			case TOKEN_BRACKET_OPEN:
				line = append(line, "[")
			case TOKEN_CONSTANT_INT:
				line = append(line, strconv.Itoa(t.value.(int)))
			case TOKEN_WORD:
				word := t.value.(string)

				c, found := getConstantS(t)

				if found {
 					line = append(line, strconv.Itoa(c.value.(int)))
				} else {
					if word == "pop" {
						popCount++
					} else if word == "push" {
						pushCount++
					}

					line = append(line, word)
				}
			default:
				addError(CompilerError{
					code: MacroParseError,
					message: UnexpectedValueMacroBody,
					token: t,
				})
			}

			if i == len(body) - 1 ||
				t.loc.l != body[i+1].loc.l {
				value.body = append(value.body, strings.Join(line, " "))
				line = make([]string, 0, 0)
			}
		}
		value.argumentCount = popCount
		value.returnCount = pushCount
		emit(Code{op: OP_ASSEMBLY, loc: t.loc, value: value})
	case TOKEN_AT:
		emit(Code{op: OP_LOAD, loc: t.loc})
	case TOKEN_AT_C:
		emit(Code{op: OP_LOAD_BYTE, loc: t.loc})
	case TOKEN_BANG:
		emit(Code{op: OP_STORE, loc: t.loc})
	case TOKEN_BANG_C:
		emit(Code{op: OP_STORE_BYTE, loc: t.loc})
	case TOKEN_BANG_EQUAL:
		emit(Code{op: OP_NOT_EQUAL, loc: t.loc})
	case TOKEN_EQUAL:
		emit(Code{op: OP_EQUAL, loc: t.loc})
	case TOKEN_GREATER:
		emit(Code{op: OP_GREATER, loc: t.loc})
	case TOKEN_GREATER_EQUAL:
		emit(Code{op: OP_GREATER_EQUAL, loc: t.loc})
	case TOKEN_LESS_EQUAL:
		emit(Code{op: OP_LESS_EQUAL, loc: t.loc})
	case TOKEN_MINUS:
		emit(Code{op: OP_SUBSTRACT, loc: t.loc})
	case TOKEN_PERCENT:
		emit(Code{op: OP_MODULO, loc: t.loc})
	case TOKEN_PLUS:
		emit(Code{op: OP_ADD, loc: t.loc})
	case TOKEN_SLASH:
		emit(Code{op: OP_DIVIDE, loc: t.loc})
	case TOKEN_STAR:
		emit(Code{op: OP_MULTIPLY, loc: t.loc})

	// FLOW CONTROL
	case TOKEN_FI:
		c := getCurrentScope()

		switch c.kind {
		case SCOPE_IF:
			emit(Code{op: OP_IF_ELSE, loc: t.loc, value: c.ipStart})
			emit(Code{op: OP_IF_END, loc: t.loc, value: c.ipStart})
			closeScopeAfterCheck(SCOPE_IF)
		case SCOPE_ELSE:
			emit(Code{op: OP_IF_END, loc: t.loc, value: c.ipStart})
			closeScopeAfterCheck(SCOPE_ELSE)
		default:
			addError(CompilerError{
				code: FunctionParseError,
				message: UnexpectedCodeBlockSyntax,
				token: t,
			}, "fi", "if or else")
		}
	case TOKEN_ELSE:
		c := getCurrentScope()

		if c.kind != SCOPE_IF {
			addError(CompilerError{
				code: FunctionParseError,
				message: UnexpectedCodeBlockSyntax,
				token: t,
			}, "else", "if")
		}

		c.kind = SCOPE_ELSE
		emit(Code{op: OP_IF_ELSE, loc: t.loc, value: c.ipStart})
	case TOKEN_IF:
		c := openScope(SCOPE_IF, t)
		emit(Code{op: OP_IF_START, loc: t.loc, value: c.ipStart})
	case TOKEN_LOOP:
		c := getCurrentScope()

		if c.kind != SCOPE_LOOP {
			addError(CompilerError{
				code: FunctionParseError,
				message: UnexpectedCodeBlockSyntax,
				token: t,
			}, "loop", "until or while")
		}

		// Note: UNTIL and WHILE have the same block closing mechanics
		_, indexName := getLimitIndexBindWords()
		b, _ := getBind(indexName)
		emit(Code{op: OP_REBIND, loc: t.loc, value: b})
		emit(Code{op: OP_LOOP_END, loc: t.loc, value: c.ipStart})
		emitLetUnbind()
		closeScopeAfterCheck(SCOPE_LOOP)
	case TOKEN_UNTIL:
		// Note: UNTIL loops take the last 3 op codes from the function body
		// and use them to create the necessary boolean arithmetics to loop
		// through it. At the end of the loop, the user should provide the
		// next index value.
		copyOfLoopStartCodeOps := takeFromFunctionCode(3)
		c := openScope(SCOPE_LOOP, t)
		limitName, indexName := getLimitIndexBindWords()
		emit(copyOfLoopStartCodeOps[0])
		emit(copyOfLoopStartCodeOps[1])
		emitLetBind(limitName, indexName)
		emit(Code{op: OP_LOOP_SETUP, loc: t.loc, value: c.ipStart})
		emitPushLet(limitName)
		emitPushLet(indexName)
		emit(copyOfLoopStartCodeOps[2])
		emit(Code{op: OP_LOOP_START, loc: t.loc, value: c.ipStart})
	case TOKEN_WHILE:
		// Note: WHILE loops are pretty simple. Before you close the block,
		// you provide the value for the next starting loop.
		c := openScope(SCOPE_LOOP, t)
		_, indexName := getLimitIndexBindWords()
		emitLetBind(indexName)
		emit(Code{op: OP_LOOP_SETUP, loc: t.loc, value: c.ipStart})
		emitPushLet(indexName)
		emit(Code{op: OP_LOOP_START, loc: t.loc, value: c.ipStart})

	// SPECIAL
	case TOKEN_LEAVE:
		emitReturn()
	case TOKEN_WORD:
		expandWordMeaning()

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
				createConstant()
			case TOKEN_FN:
				createFunction()
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
				createVariable()
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

			if t.kind == TOKEN_FN {
				advance()
				wordT := parser.previousToken
				setCurrentFunctionToParse(wordT)
				stack.setup()

				for !match(TOKEN_PAREN_CLOSE) { advance() }

				for !check(TOKEN_RET) && !check(TOKEN_EOF) {
					advance()
					if !parser.currentFn.error { parseTokens() }
				}

				consume(TOKEN_RET, UnexpectedSymbol, "ret")
				emitReturn()
				parser.currentFn.parsed = true
				stack.validate()
				stack.reset()
				parser.currentFn = nil
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
