package skc

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type ScopeName string

const (
	UndefinedScope ScopeName = ""
	GlobalScope   = "global"
	FunctionScope = "function"
	BindScope     = "bind"
	LoopScope     = "loop"
	IfScope       = "if"
	ElseScope     = "else"
)

type Function struct {
	ip              int
	word            string
	loc             Location
	token           Token

	arguments       Arity
	results         Arity
	bindings        Binding
	code            []Code
	scope           []Scope
	constants       []Constant
	variables       []Variable

	localMemorySize int
	error           bool
	parsed          bool
	called          bool
	internal        bool
}

type Parser struct {
	// array of tokens passed into the next macro used. It can
	// only be populated once, so if the user tries to generate a new
	// body before flushing this stack, it should get an error.
	bodyStack     []Token
	currentFn     *Function
	error         bool
	globalWords   []string

	previousToken Token
	currentToken  Token
	index         int
	internal      bool
	tokens        []Token
}

type Program struct {
	chunks           []Function
	constants        []Constant
	errors           []ProgramError
	libcEnabled      bool
	parser           Parser
	simulation       Simulation
	staticMemorySize int
	variables        []Variable
}

type Stack []ValueKind

type Simulation struct {
	calledIPs   []int
	currentCode *Code
	currentFn   *Function
	mainHandled bool
	scope       int
	snapshots   [10]Stack
	stack       Stack
}

func (this *Program) saveErrorAtToken(t Token, msg ErrorMessage, args ...any) {
	this.parser.currentFn.error = true

	pErr := ProgramError{
		code: ParseError,
		err: fmt.Sprintf(string(msg), args...),
		token: t,
	}
	this.errors = append(this.errors, pErr)
}

func (this *Program) validate() {
	if len(this.errors) > 0 {
		ExitWithError(ValidationError)
	}
}

func (this *Program) write(code Code) {
	fn := this.parser.currentFn
	fn.code = append(fn.code, code)
}

var file FileManager
var parser = &TheProgram.parser

/*   ___ ___ ___  ___  ___  ___
 *  | __| _ \ _ \/ _ \| _ \/ __|
 *  | _||   /   / (_) |   /\__ \
 *  |___|_|_\_|_\\___/|_|_\|___/
 */
func errorAt(token *Token, format string, values ...any) {
	parser.error = true

	msg := fmt.Sprintf(format, values...)
	ReportErrorAtLocation(msg, token.loc)
}

/*   ___  _   ___  ___ ___ ___
 *  | _ \/_\ | _ \/ __| __| _ \
 *  |  _/ _ \|   /\__ \ _||   /
 *  |_|/_/ \_\_|_\|___/___|_|_\
 */
func startParser(f File) {
	parser.index = 0
	parser.tokens = TokenizeFile(f.filename, f.source)
	parser.currentToken = parser.tokens[parser.index]
	parser.internal = f.internal
}

func advance() {
	parser.index++
	parser.previousToken = parser.currentToken
	parser.currentToken = parser.tokens[parser.index]
}

func consume(tt TokenType, err string) {
	if tt == parser.currentToken.kind {
		advance()
		return
	}

	errorAt(&parser.currentToken, err)
}

func check(tt TokenType) bool {
	return tt == parser.currentToken.kind
}

func isParsingFunction() bool {
	return parser.currentFn != nil
}

func match(tt TokenType) bool {
    if !check(tt) {
		return false;
	}
    advance();
    return true;
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

/*   ___ ___
 *  |_ _| _ \
 *   | ||   /
 *  |___|_|_\
 */
// We need to add the bindings at the start of the array, because the memory
// space is moved backwards and now, the top of top of the static memory is taken
// by these values, and the previous existing values are offset by `count` QWORD.
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

func openScope(s ScopeName, t Token) *Scope {
	newScope := Scope{
		ipStart: len(parser.currentFn.code),
		tokenStart: t,
		kind: s,
	}
	parser.currentFn.scope = append(parser.currentFn.scope, newScope)
	lastScopeIndex := len(parser.currentFn.scope)-1
	return &parser.currentFn.scope[lastScopeIndex]
}

func getCurrentScope() *Scope {
	lastScopeIndex := len(parser.currentFn.scope)-1
	return &parser.currentFn.scope[lastScopeIndex]
}

func getCountForScopeName(s ScopeName) int {
	var count int
	for _, ss := range parser.currentFn.scope {
		if ss.kind == s {
			count++
		}
	}
	return count
}

func closeScopeAfterCheck(s ScopeName) {
	lastScopeIndex := len(parser.currentFn.scope)-1
	lastOpenedScope := parser.currentFn.scope[lastScopeIndex]

	if lastOpenedScope.kind == s {
		parser.currentFn.scope = parser.currentFn.scope[:lastScopeIndex]
	} else {
		errorAt(&parser.previousToken, "TODO: Error closing scope")
	}
}

func getLimitIndexBindWord() (string, string) {
	loopIndexByte := 72
	loopScopeDepth := getCountForScopeName(LoopScope)
	loopIndexByte += loopScopeDepth
	loopIndexWord := string(byte(loopIndexByte))
	limitWord := loopIndexWord + "limit"
	return limitWord, loopIndexWord
}

func emit(code Code) {
	TheProgram.write(code)
}

func emitConstantValue(kind ValueKind, value any) {
	code := Code{loc: parser.previousToken.loc, value: value}

	switch kind {
	case BOOL:   code.op = OP_PUSH_BOOL
	case BYTE:   code.op = OP_PUSH_BYTE
	case INT:    code.op = OP_PUSH_INT
	case STRING: code.op = OP_PUSH_STR
	}

	emit(code)
}

func emitFromConstants(word string) bool {
	c, found := getConstant(word)

	if found { emitConstantValue(c.kind, c.value) }

	return found
}

func emitFromVariables(word string) bool {
	t := parser.previousToken
	v, found := getVariable(word)

	if found {
		switch v.scope {
		case FunctionScope:
			emit(Code{op: OP_PUSH_VAR_LOCAL, loc: t.loc, value: v.offset})
		case GlobalScope:
			emit(Code{op: OP_PUSH_VAR_GLOBAL, loc: t.loc, value: v.offset})
		}
	}

	return found
}

func emitReturn() {
	emit(Code{
		op: OP_RET,
		loc: parser.previousToken.loc,
		value: 0,
	})
}

/*   ___ ___ ___ ___ ___  ___   ___ ___ ___ ___  ___  ___
 *  | _ \ _ \ __| _ \ _ \/ _ \ / __| __/ __/ __|/ _ \| _ \
 *  |  _/   / _||  _/   / (_) | (__| _|\__ \__ \ (_) |   /
 *  |_| |_|_\___|_| |_|_\\___/ \___|___|___/___/\___/|_|_\
 */
func createConstant() {
	var newConst Constant

	if !match(TOKEN_WORD) {
		t := parser.previousToken

		if isParsingFunction() {
			TheProgram.saveErrorAtToken(t, DeclarationWordMissing)
		} else {
			ReportErrorAtLocation(DeclarationWordMissing, t.loc)
			ExitWithError(ParseError)
		}
	}

	wordT := parser.previousToken
	newConst.word = wordT.value.(string)

	if isWordInUse(wordT) {
		if isParsingFunction() {
			TheProgram.saveErrorAtToken(wordT, DeclarationWordAlreadyUsed, newConst.word)
		} else {
			ReportErrorAtLocation(
				DeclarationWordAlreadyUsed,
				wordT.loc,
				newConst.word,
			)
			ExitWithError(ParseError)
		}
	}

	advance()
	valueT := parser.previousToken
	newConst.token = valueT

	switch valueT.kind {
	case TOKEN_CONSTANT_BYTE:
		newConst.kind = BYTE
		newConst.value = valueT.value
	case TOKEN_CONSTANT_FALSE:
		newConst.kind = BOOL
		newConst.value = 0
	case TOKEN_CONSTANT_INT:
		newConst.kind = INT
		newConst.value = valueT.value
	case TOKEN_CONSTANT_STR:
		newConst.kind = STRING
		newConst.value = valueT.value
	case TOKEN_CONSTANT_TRUE:
		newConst.kind = BOOL
		newConst.value = 1
	default:
		if isParsingFunction() {
			TheProgram.saveErrorAtToken(valueT, ConstantValueKindNotAllowed)
		} else {
			ReportErrorAtLocation(ConstantValueKindNotAllowed, valueT.loc)
			ExitWithError(ParseError)
		}
	}

	if isParsingFunction() {
		parser.currentFn.constants = append(parser.currentFn.constants, newConst)
	} else {
		parser.globalWords = append(parser.globalWords, newConst.word)
		TheProgram.constants = append(TheProgram.constants, newConst)
	}
}

func createVariable() {
	var newVar Variable
	var currentOffset int
	var newOffset int
	const SIZE_64b = 8

	if isParsingFunction() {
		currentOffset = parser.currentFn.localMemorySize
		newVar.scope = FunctionScope
	} else {
		currentOffset = TheProgram.staticMemorySize
		newVar.scope = GlobalScope
	}

	if !match(TOKEN_WORD) {
		t := parser.previousToken
		if isParsingFunction() {
			TheProgram.saveErrorAtToken(t, DeclarationWordMissing)
		} else {
			ReportErrorAtLocation(DeclarationWordMissing, t.loc)
			ExitWithError(ParseError)
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
			TheProgram.saveErrorAtToken(wordT, DeclarationWordAlreadyUsed, newVar.word)
		} else {
			ReportErrorAtLocation(
				DeclarationWordAlreadyUsed,
				wordT.loc,
				newVar.word,
			)
			ExitWithError(ParseError)
		}
	}

	advance()
	valueT := parser.previousToken

	switch valueT.kind {
	case TOKEN_BOOL:
		newVar.kind = BOOL
	case TOKEN_BYTE:
		newVar.kind = BYTE
	case TOKEN_INT:
		newVar.kind = INT
	case TOKEN_PTR:
		newVar.kind = RAWPOINTER
	case TOKEN_STR:
		newVar.kind = STRING
	default:
		if isParsingFunction() {
			TheProgram.saveErrorAtToken(valueT, VariableValueKindNotAllowed)
		} else {
			ReportErrorAtLocation(VariableValueKindNotAllowed, valueT.loc)
			ExitWithError(ParseError)
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

func registerFunction(token Token) {
	var function Function

	function.internal = parser.internal
	function.ip = len(TheProgram.chunks)
	function.token = token
	function.parsed = false

	if !match(TOKEN_WORD) {
		errorAt(&token, MsgParseFunctionMissingName)
		ExitWithError(CodeParseError)
	}

	tokenWord := parser.previousToken
	function.word = tokenWord.value.(string)

	if function.word == "main" {
		for _, f := range TheProgram.chunks {
			if f.word == "main" {
				msg := fmt.Sprintf(MsgParseFunctionMainAlreadyDefined,
					GetRelativePath(f.loc.f), f.loc.l)
				errorAt(&token, msg)
				ExitWithError(CodeParseError)
			}
		}
	}

	consume(TOKEN_PAREN_OPEN, MsgParseFunctionMissingOpenStmt)

	parsingArguments := true

	for !check(TOKEN_PAREN_CLOSE) && !check(TOKEN_EOF) {
		advance()
		t := parser.previousToken

		if t.kind == TOKEN_DASH_DASH_DASH {
			parsingArguments = false
			continue
		}

		parseArityInFunction(t, &function, parsingArguments)
	}

	consume(TOKEN_PAREN_CLOSE, MsgParseFunctionMissingCloseStmt)

	// Verify if the function signature is different from a previous function declared
	// with the same name. Error out if it matches signature arguments, or if it has different
	// return values.
	fcode, found := getFunction(tokenWord)

	if found {
		for _, ip := range fcode.value.([]int) {
			f := TheProgram.chunks[ip]

			if reflect.DeepEqual(f.arguments, function.arguments) {
				msg := fmt.Sprintf(MsgParseArityArgumentSameSignatureError,
					GetRelativePath(f.loc.f), f.loc.l)
				errorAt(&tokenWord, msg)
				ExitWithError(CodeParseError)
			}

			if !reflect.DeepEqual(f.results, function.results) {
				msg := fmt.Sprintf(MsgParseArityReturnDifferentSignatureError,
					GetRelativePath(f.loc.f), f.loc.l)
				errorAt(&tokenWord, msg)
				ExitWithError(CodeParseError)
			}
		}
	}

	// Skip the function content, since we're just registering it.
	for !check(TOKEN_RET) && !check(TOKEN_EOF) {
		advance()
	}

	consume(TOKEN_RET, MsgParseFunctionMissingRetWord)

	TheProgram.chunks = append(TheProgram.chunks, function)
}

/*    ___ ___  __  __ ___ ___ _      _ _____ ___ ___  _  _
 *   / __/ _ \|  \/  | _ \_ _| |    /_\_   _|_ _/ _ \| \| |
 *  | (_| (_) | |\/| |  _/| || |__ / _ \| |  | | (_) | .` |
 *   \___\___/|_|  |_|_| |___|____/_/ \_\_| |___\___/|_|\_|
 */
func takeFromFunctionCode(quant int) []Code {
	var result []Code
	codeLength := len(parser.currentFn.code)

	for index := codeLength-quant; index < codeLength; index++ {
		result = append(result, parser.currentFn.code[index])
	}

	parser.currentFn.code = parser.currentFn.code[:codeLength-quant]
	return result
}

func getBind(token Token) (Code, bool) {
	word := token.value.(string)

	for bindex, bind := range parser.currentFn.bindings.words {
		if bind == word {
			return Code{op: OP_PUSH_BIND, loc: token.loc, value: bindex}, true
		}
	}

	return Code{}, false
}

func getConstant(word string) (*Constant, bool) {
	if isParsingFunction() {
		for _, c := range parser.currentFn.constants {
			if c.word == word {
				return &c, true
			}
		}
	}

	for _, c := range TheProgram.constants {
		if c.word == word {
			return &c, true
		}
	}

	return nil, false
}

func getVariable(word string) (*Variable, bool) {
	if isParsingFunction() {
		for _, v := range parser.currentFn.variables {
			if v.word == word {
				return &v, true
			}
		}
	}

	for _, v := range TheProgram.variables {
		if v.word == word {
			return &v, true
		}
	}

	return nil, false
}

func getFunction(token Token) (Code, bool) {
	var val []int
	word := token.value.(string)

	for _, f := range TheProgram.chunks {
		if f.word == word {
			val = append(val, f.ip)
		}
	}

	if len(val) > 0 {
		return Code{op: OP_FUNCTION_CALL, loc: token.loc, value: val}, true
	}

	return Code{}, false
}

func expandWord(token Token) {
	t := parser.previousToken
	word := t.value.(string)
	b, bfound := getBind(token)

	if bfound {
		emit(b)
		return
	}

	// Find the word in functions. If it results one, emit it
	code_f, ok_f := getFunction(token)

	if ok_f {
		emit(code_f)
		return
	}

	if !(emitFromConstants(word) || emitFromVariables(word)) {
		// If nothing has been found, emit the error.
		msg := fmt.Sprintf(MsgParseWordNotFound, word)
		ReportErrorAtLocation(msg, t.loc)
		ExitWithError(CodeCodegenError)
	}
}

func parseToken() {
	var code Code
	token := parser.previousToken
	code.loc = token.loc
	code.value = token.value

	switch token.kind {
	// CONSTANTS
	case TOKEN_CONSTANT_BYTE:
		emitConstantValue(BYTE, token.value)
	case TOKEN_CONSTANT_FALSE:
		emitConstantValue(BOOL, 0)
	case TOKEN_CONSTANT_INT:
		emitConstantValue(INT, token.value)
	case TOKEN_CONSTANT_STR:
		emitConstantValue(STRING, token.value)
	case TOKEN_CONSTANT_TRUE:
		emitConstantValue(BOOL, 1)

	case TOKEN_AMPERSAND:
		b, bfound := getBind(token)
		if bfound {
			code.op = OP_PUSH_BIND_ADDR
			code.value = b.value
			emit(code)
			return
		}
		v, vfound := getVariable(token.value.(string))
		if vfound {
			switch v.scope {
			case FunctionScope: code.op = OP_PUSH_VAR_LOCAL_ADDR
			case GlobalScope: code.op = OP_PUSH_VAR_GLOBAL_ADDR
			}
			code.value = v.offset
			emit(code)
		}

	// TYPE CASTING
	case TOKEN_BOOL:
		code.op = OP_CAST
		code.value = BOOL
		emit(code)
	case TOKEN_BYTE:
		code.op = OP_CAST
		code.value = BYTE
		emit(code)
	case TOKEN_INT:
		code.op = OP_CAST
		code.value = INT
		emit(code)
	case TOKEN_PTR:
		code.op = OP_CAST
		code.value = RAWPOINTER
		emit(code)

	// DEFINITION
	case TOKEN_CONST:
		createConstant()
	case TOKEN_CURLY_BRACKET_OPEN:
		var tokens []Token

		if len(parser.bodyStack) > 0 {
			errorAt(&token, "TODO: Cannot parse another body")
			ExitWithError(CodeParseError)
		}

		for !check(TOKEN_CURLY_BRACKET_CLOSE) && !check(TOKEN_EOF) {
			advance()
			tokens = append(tokens, parser.previousToken)
		}

		if len(tokens) == 0 {
			errorAt(&token, "TODO: error body cannot be empty")
			ExitWithError(CodeParseError)
		}

		consume(TOKEN_CURLY_BRACKET_CLOSE, "TODO: Missing curly bracket")
		parser.bodyStack = tokens
	case TOKEN_VAR:
		createVariable()

	// Intrinsics
	case TOKEN_ARGC:
		code.op = OP_ARGC
		emit(code)
	case TOKEN_ARGV:
		code.op = OP_ARGV
		emit(code)
	case TOKEN_ASM:
		// NOTE: This is a special instrinsic macro that uses the @body and
		// calculates the stack modifications necessary to make sure the
		// function signature is respected.
		var popCount int
		var pushCount int
		var line []string
		var value ASMValue
		body := parser.bodyStack
		parser.bodyStack = make([]Token, 0, 0)

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

				c, found := getConstant(word)

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
				errorAt(&t, "TODO: Token not allowed")
				ExitWithError(CodeParseError)
			}

			if i == len(body) - 1 ||
				t.loc.l != body[i+1].loc.l {
				value.body = append(value.body, strings.Join(line, " "))
				line = make([]string, 0, 0)
			}
		}
		value.argumentCount = popCount
		value.returnCount = pushCount
		code.op = OP_ASSEMBLY
		code.value = value
		emit(code)
	case TOKEN_BANG_EQUAL:
		code.op = OP_NOT_EQUAL
		emit(code)
	case TOKEN_EQUAL:
		code.op = OP_EQUAL
		emit(code)
	case TOKEN_GREATER:
		code.op = OP_GREATER
		emit(code)
	case TOKEN_GREATER_EQUAL:
		code.op = OP_GREATER_EQUAL
		emit(code)
	case TOKEN_LEAVE:
		emitReturn()
	case TOKEN_LESS:
		code.op = OP_LESS
		emit(code)
	case TOKEN_LESS_EQUAL:
		code.op = OP_LESS_EQUAL
		emit(code)
	case TOKEN_LET:
		var newWords []string

		for match(TOKEN_WORD) {
			word := parser.previousToken.value.(string)
			newWords = append(newWords, word)
		}

		consume(TOKEN_IN, MsgParseLetMissingIn)
		openScope(BindScope, token)

		code.op = OP_LET_BIND
		code.value = bind(newWords)
		emit(code)
	case TOKEN_DONE:
		closeScopeAfterCheck(BindScope)
		code.op = OP_LET_UNBIND
		code.value = unbind()
		emit(code)
	case TOKEN_MINUS:
		code.op = OP_SUBSTRACT
		emit(code)
	case TOKEN_PERCENT:
		code.op = OP_MODULO
		emit(code)
	case TOKEN_PLUS:
		code.op = OP_ADD
		emit(code)
	case TOKEN_SLASH:
		code.op = OP_DIVIDE
		emit(code)
	case TOKEN_STAR:
		code.op = OP_MULTIPLY
		emit(code)
	case TOKEN_THIS:
		loc := code.loc
		code.op = OP_PUSH_STR
		code.value = fmt.Sprintf("%s:%d:%d", loc.f, loc.l, loc.c)
		emit(code)

	// POINTER INTRINSICS
	case TOKEN_AT:
		code.op = OP_LOAD
		emit(code)
	case TOKEN_AT_BYTE:
		code.op = OP_LOAD_BYTE
		emit(code)
	case TOKEN_BANG:
		code.op = OP_STORE
		emit(code)
	case TOKEN_BANG_BYTE:
		code.op = OP_STORE_BYTE
		emit(code)

	// Special
	case TOKEN_WORD: expandWord(token)

	// FLOW CONTROL
	case TOKEN_UNTIL:
		// UNTIL Loops work in a way where we get the last 3 op codes, OP codes are the ones
		// hopefully providing a boolean as a result. We use them initially to make sure
		// we want to go through the LOOP (as in, if the result is true, we start preparation).
		// Preparation step begins by binding the left and right operators into the limit
		// and index words, and then use the bound values to do another check and continue.
		// That would be, if it's true, jumps into the loop, if it's false, goes to the end
		// label.
		copyOfLoopStartCodeOps := takeFromFunctionCode(3)

		c := openScope(LoopScope, token)

		// We bind the limit and the index values for future use.
		limitN, indexN := getLimitIndexBindWord()
		emit(copyOfLoopStartCodeOps[0])
		emit(copyOfLoopStartCodeOps[1])
		emit(Code{op: OP_LET_BIND, loc: code.loc, value: bind([]string{limitN, indexN})})
		emit(Code{op: OP_LOOP_SETUP, loc: code.loc, value: c.ipStart})
		bc, _ := getBind(Token{loc: token.loc, value: limitN})
		emit(bc)
		bc, _ = getBind(Token{loc: token.loc, value: indexN})
		emit(bc)
		emit(copyOfLoopStartCodeOps[2])
		emit(Code{op: OP_LOOP_START, loc: code.loc, value: c.ipStart})
	case TOKEN_WHILE:
		c := openScope(LoopScope, token)
		_, indexN := getLimitIndexBindWord()
		emit(Code{op: OP_LET_BIND, loc: code.loc, value: bind([]string{indexN})})
		emit(Code{op: OP_LOOP_SETUP, loc: code.loc, value: c.ipStart})
		bc, _ := getBind(Token{loc: token.loc, value: indexN})
		emit(bc)
		emit(Code{op: OP_LOOP_START, loc: code.loc, value: c.ipStart})
	case TOKEN_LOOP:
		c := getCurrentScope()

		if c.kind != LoopScope {
			// TODO: Improve error message, showing the starting and closing statements
			errorAt(&c.tokenStart, "TODO: ERROR MESSAGE")
			errorAt(&token, "TODO: ERROR MESSAGE")
			ExitWithError(CodeParseError)
		}

		switch c.tokenStart.kind {
		case TOKEN_UNTIL:
			_, indexN := getLimitIndexBindWord()
			bc, _ := getBind(Token{loc: token.loc, value: indexN})
			emit(Code{op: OP_REBIND, loc: code.loc, value: bc.value})
			emit(Code{op: OP_LOOP_END, loc: code.loc, value: c.ipStart})
			emit(Code{op: OP_LET_UNBIND, loc: code.loc, value: unbind()})
		case TOKEN_WHILE:
			_, indexN := getLimitIndexBindWord()
			bc, _ := getBind(Token{loc: token.loc, value: indexN})
			emit(Code{op: OP_REBIND, loc: code.loc, value: bc.value})
			emit(Code{op: OP_LOOP_END, loc: code.loc, value: c.ipStart})
			emit(Code{op: OP_LET_UNBIND, loc: code.loc, value: unbind()})
		}

		closeScopeAfterCheck(LoopScope)
	case TOKEN_IF:
		c := openScope(IfScope, token)

		code.op = OP_IF_START
		code.value = c.ipStart
		emit(code)
	case TOKEN_FI:
		c := getCurrentScope()

		switch c.kind {
		case IfScope:
			code.op = OP_IF_ELSE
			code.value = c.ipStart
			emit(code)
			code.op = OP_IF_END
			emit(code)
			closeScopeAfterCheck(IfScope)
		case ElseScope:
			code.op = OP_IF_END
			code.value = c.ipStart
			emit(code)
			closeScopeAfterCheck(ElseScope)
		default:
			errorAt(&c.tokenStart, "TODO: ERROR MESSAGE")
			errorAt(&token, "TODO: ERROR MESSAGE")
			ExitWithError(CodeParseError)
		}
	case TOKEN_ELSE:
		c := getCurrentScope()
		previousIpStart := c.ipStart

		if c.kind != IfScope {
			errorAt(&c.tokenStart, "TODO: ERROR MESSAGE")
			errorAt(&token, "TODO: ERROR MESSAGE")
			ExitWithError(CodeParseError)
		}

		closeScopeAfterCheck(IfScope)
		c = openScope(ElseScope, token)
		c.ipStart = previousIpStart
		code.op = OP_IF_ELSE
		code.value = c.ipStart
		emit(code)
	}
}

func parseArityInAssembly(token Token, args *Arity) {
	var newArg Argument

	switch token.kind {
	case TOKEN_BOOL:
		newArg.kind = BOOL
	case TOKEN_BYTE:
		newArg.kind = BYTE
	case TOKEN_INT:
		newArg.kind = INT
	case TOKEN_PTR:
		newArg.kind = RAWPOINTER
	case TOKEN_STR:
		newArg.kind = STRING
	default:
		msg := fmt.Sprintf(MsgParseTypeUnknown, token.value.(string))
		errorAt(&token, msg)
		ExitWithError(CodeParseError)
	}

	args.types = append(args.types, newArg)
}

func parseArityInFunction(token Token, function *Function, parsingArguments bool) {
	var newArg Argument

	switch token.kind {
	case TOKEN_ANY:
		if !parser.internal {
			errorAt(&token, MsgParseArityArgumentAnyOnlyInternal)
			ExitWithError(CodeParseError)
		}

		newArg.kind = ANY
	case TOKEN_BOOL:
		newArg.kind = BOOL
	case TOKEN_BYTE:
		newArg.kind = BYTE
	case TOKEN_INT:
		newArg.kind = INT
	case TOKEN_PTR:
		newArg.kind = RAWPOINTER
	case TOKEN_STR:
		newArg.kind = STRING
	case TOKEN_PARAPOLY:
		if !parsingArguments {
			errorAt(&token, MsgParseArityReturnParapolyNotAllowed)
			ExitWithError(CodeParseError)
		}

		newArg.kind = VARIADIC
		newArg.word = token.value.(string)
		function.arguments.parapoly = true
	case TOKEN_WORD:
		w := token.value.(string)

		if parsingArguments {
			msg := fmt.Sprintf(MsgParseTypeUnknown, w)
			errorAt(&token, msg)
			ExitWithError(CodeParseError)
		}

		funcArgs := function.arguments
		argTest := Argument{word: w, kind: VARIADIC}

		if funcArgs.parapoly && Contains(funcArgs.types, argTest) {
			newArg.kind = VARIADIC
			newArg.word = w
			function.results.parapoly = true
		} else {
			msg := fmt.Sprintf(MsgParseArityReturnParapolyNotFound, w)
			errorAt(&token, msg)
			ExitWithError(CodeParseError)
		}
	default:
		msg := fmt.Sprintf(MsgParseTypeUnknown, token.value.(string))
		errorAt(&token, msg)
		ExitWithError(CodeParseError)
	}

	if parsingArguments {
		function.arguments.types = append(function.arguments.types, newArg)
	} else {
		function.results.types = append(function.results.types, newArg)
	}
}

func parseFunction(token Token) {
	// Recreate a temporary function entry to match with the already registered
	// functions in TheProgram. That's why this step doesn't have any error checking.
	var testFunc Function

	advance()
	testFunc.word = parser.previousToken.value.(string)
	advance()

	parsingArguments := true

	for !match(TOKEN_PAREN_CLOSE) {
		advance()
		t := parser.previousToken

		if t.kind == TOKEN_DASH_DASH_DASH {
			parsingArguments = false
			continue
		}

		parseArityInFunction(t, &testFunc, parsingArguments)
	}

	for index, f := range TheProgram.chunks {
		if !f.parsed && f.word == testFunc.word &&
			reflect.DeepEqual(f.arguments, testFunc.arguments) {
			parser.currentFn = &TheProgram.chunks[index]
			break
		}
	}

	if isParsingFunction() {
		for !match(TOKEN_RET) {
			advance()
			if !parser.currentFn.error { parseToken() }
		}

		emitReturn()

		// Marking the function as "parsed", then clearing out the bindings, and
		// removing the pointer to this function, so we can safely check for the next one.
		parser.currentFn.parsed = true
		parser.currentFn = nil
	} else {
		// This would be a catastrophic issue. Since we already registered functions,
		// there's no way we don't find a function with the same word that has not been
		// parsed yet. Since we can't recover from this error, we must exit.
		msg := fmt.Sprintf(MsgParseFunctionSignatureNotFound, testFunc.word)
		errorAt(&parser.previousToken, msg)
		ExitWithError(CodeParseError)
	}
}

/*
 * Compilation: First Pass
 *   This step registers the words the program will use.
 */
func compilationFirstPass(index int) {
	f := file.files[index]

	startParser(f)

	for !check(TOKEN_EOF) {
		advance()
		token := parser.previousToken

		switch token.kind {
		// The second pass will care about the following tokens:
		case TOKEN_CONST:
			createConstant()
		case TOKEN_FN:
			registerFunction(token)
		case TOKEN_USING:
			advance()

			if parser.previousToken.kind != TOKEN_WORD {
				errorAt(&parser.previousToken, "TODO: ERROR USING")
				ExitWithError(CodeParseError)
			}

			file.Open(parser.previousToken.value.(string))
		case TOKEN_VAR:
			createVariable()

		// Now, if it matches with something else, then error.
		default:
			ReportErrorAtLocation(MsgParseErrorProgramScope, token.loc)
			ExitWithError(CodeParseError)
		}
	}
}

/*
 * Compilation: Second Pass
 *   This step goes through each function and compiles the code for each one
 *   of them. Register and make all the OP codes for these functions.
 */
func compilationSecondPass(index int) {
	f := file.files[index]

	startParser(f)

	for !check(TOKEN_EOF) {
		advance()
		token := parser.previousToken

		if token.kind == TOKEN_FN {
			parseFunction(token)
		}
	}
}

func FrontendRun() {
	// Core standard library
	file.Open("runtime")

	// User entry file
	file.Open(Stanczyk.workspace.entry)

	// I'm not using "range" because Go creates a copy of the Array
	// (turning it into a slice), so if I find a new file while
	// going through the compilation, it will not update the `for` statement.
	for index := 0; index < len(file.files); index++ {
		compilationFirstPass(index)
	}

	for index := 0; index < len(file.files); index++ {
		compilationSecondPass(index)
	}

	TheProgram.validate()

	if parser.error {
		ExitWithError(CodeParseError)
	}
}
