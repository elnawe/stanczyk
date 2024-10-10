package skc

import (
	"fmt"
	"slices"
)

type Parser struct {
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

func consume(kind TokenType, err string) {
	if kind == parser.currentToken.kind {
		advance()
		return
	}

	addError(CompilerError{
		code: CodeParseError,
		message: err,
		token: parser.currentToken,
	})
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

func isWordInUse(token Token) bool {
	// TODO: Not implemented
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
		newConst.value.variant = false
	case TOKEN_CONSTANT_INT:
		newConst.value.kind = INT64
		newConst.value.variant = valueT.value
	case TOKEN_CONSTANT_STR:
		newConst.value.kind = STRING
		newConst.value.variant = valueT.value
	case TOKEN_CONSTANT_TRUE:
		newConst.value.kind = BOOLEAN
		newConst.value.variant = true
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

	return newConst
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

func Compile() {
	// Required Runtime Library
	file.Open("runtime")

	// User entry file(s)
	file.Open(Stanczyk.workspace.entry)

	// Compilation:
	//   Step 1: Add to the compilation process all other files.
	for i := 0; i < len(file.files); i++ {
		f := file.files[i]
		startParser(f)

		for !check(TOKEN_EOF) {
			advance()
			t := parser.previousToken

			if t.kind == TOKEN_USING {
				advance()
				nt := parser.previousToken

				if nt.kind != TOKEN_WORD {
					addError(CompilerError{
						code: UsingError,
						message: WordMissingAfterUsing,
						token: t,
					})
					continue
				}

				file.Open(nt.value.(string))
			}
		}
	}

	//   Step 2: Register globals (const, var, fn)
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
				// TODO Register fun
			case TOKEN_USING:
				// NOTE: Using is skipped because it's already managed on the
				// first compilation step. No need to do anything here. So
				// we move the pointer one over and then continue.
				advance()
				continue
			case TOKEN_VAR:
				// TODO Register var

			default:
				// Handle errors for non-global allowed tokens.
				// These kind of errors are usually non-recoverable, this is
				// because the parsing will be corrupt, at least for this file.
				ReportErrorAtLocation(NonDeclarationInGlobalScope, t.loc)
				ExitWithError(CriticalError)
			}
		}
	}

	//   Step 3: Compile function contents
	for i := 0; i < len(TheProgram.chunks); i++ {
		fn := &TheProgram.chunks[i]
		parser.currentFn = fn
		// TODO
	}

	if len(TheProgram.errors) > 0 {
		for _, e := range TheProgram.errors {
			ReportErrorAtLocation(e.message, e.token.loc)
		}
		ExitWithError(CompilationError)
	}
}
