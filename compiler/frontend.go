package skc

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type ObjectType int

const (
	OBJ_CONSTANT ObjectType = iota
)

type Object struct {
	dtype DataType
	value any
	typ   ObjectType
	word  string
}

type Frontend struct {
	// array of tokens passed into the next macro used. It can
	// only be populated once, so if the user tries to generate a new
	// body before flushing this stack, it should get an error.
	bodyStack  []Token
	current	   *Function
	error      bool
}

type Parser struct {
	previous Token
	current  Token
	tokens   []Token
	internal bool
	index    int
}

var file FileManager
var frontend Frontend
var parser Parser

/*   ___ ___ ___  ___  ___  ___
 *  | __| _ \ _ \/ _ \| _ \/ __|
 *  | _||   /   / (_) |   /\__ \
 *  |___|_|_\_|_\\___/|_|_\|___/
 */
func errorAt(token *Token, format string, values ...any) {
	frontend.error = true

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
	parser.current = parser.tokens[parser.index]
	parser.internal = f.internal
}

func advance() {
	parser.index++
	parser.previous = parser.current
	parser.current = parser.tokens[parser.index]
}

func jumpTo(index int) {
	parser.index = index
	parser.current = parser.tokens[index]
	advance()
}

func consume(tt TokenType, err string) {
	if tt == parser.current.typ {
		advance()
		return
	}

	errorAt(&parser.current, err)
}

func check(tt TokenType) bool {
	return tt == parser.current.typ
}

func match(tt TokenType) bool {
    if !check(tt) {
		return false;
	}
    advance();
    return true;
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
	bindings := &frontend.current.bindings
	count := len(nw)
	bindings.count = append([]int{count}, bindings.count...)
	bindings.words = append(nw, bindings.words...)
	return count
}

func unbind() int {
	bindings := &frontend.current.bindings
	unbindAmount := frontend.current.bindings.count[0]
	bindings.count = bindings.count[1:]
	bindings.words = bindings.words[unbindAmount:]
	return unbindAmount
}

func openScope(s ScopeType, t Token) *Scope {
	newScope := Scope{
		ipStart: len(frontend.current.code),
		tokenStart: t,
		typ: s,
	}
	frontend.current.scope = append(frontend.current.scope, newScope)
	lastScopeIndex := len(frontend.current.scope)-1
	return &frontend.current.scope[lastScopeIndex]
}

func getCurrentScope() *Scope {
	lastScopeIndex := len(frontend.current.scope)-1
	return &frontend.current.scope[lastScopeIndex]
}

func getCountForScopeType(s ScopeType) int {
	var count int
	for _, ss := range frontend.current.scope {
		if ss.typ == s {
			count++
		}
	}
	return count
}

func closeScopeAfterCheck(s ScopeType) {
	lastScopeIndex := len(frontend.current.scope)-1
	lastOpenedScope := frontend.current.scope[lastScopeIndex]

	if lastOpenedScope.typ == s {
		frontend.current.scope = frontend.current.scope[:lastScopeIndex]
	} else {
		errorAt(&parser.previous, "TODO: Error closing scope")
	}
}

func getLimitIndexBindWord() (string, string) {
	loopIndexByte := 72
	loopScopeDepth := getCountForScopeType(SCOPE_LOOP)
	loopIndexByte += loopScopeDepth
	loopIndexWord := string(byte(loopIndexByte))
	limitWord := loopIndexWord + "limit"
	return limitWord, loopIndexWord
}

func emit(code Code) {
	frontend.current.WriteCode(code)
}

func emitReturn() {
	emit(Code{
		op: OP_RET,
		loc: parser.previous.loc,
		value: 0,
	})
}

/*   ___ ___ ___ ___ ___  ___   ___ ___ ___ ___  ___  ___
 *  | _ \ _ \ __| _ \ _ \/ _ \ / __| __/ __/ __|/ _ \| _ \
 *  |  _/   / _||  _/   / (_) | (__| _|\__ \__ \ (_) |   /
 *  |_| |_|_\___|_| |_|_\\___/ \___|___|___/___/\___/|_|_\
 */
func newConstant(token Token) Constant {
	var constant Constant
	var tokens []Token

	if !match(TOKEN_WORD) {
		errorAt(&parser.previous, MsgParseConstMissingWord)
		ExitWithError(CodeParseError)
	}

	wordToken := parser.previous
	constant.word = wordToken.value.(string)

	// TODO: Support rebiding constants in same scope if build configuration allows for it.
	_, found := getConstant(wordToken)

	if found {
		msg := fmt.Sprintf(MsgParseConstOverrideNotAllowed, constant.word)
		errorAt(&token, msg)
		ExitWithError(CodeParseError)
	}

	if match(TOKEN_PAREN_CLOSE) {
		msg := fmt.Sprintf(MsgParseConstInvalidContent, constant.word)
		errorAt(&token, msg)
	}

	if match(TOKEN_PAREN_OPEN) {
		for !check(TOKEN_PAREN_CLOSE) && !check(TOKEN_EOF) {
			advance()
			tokens = append(tokens, parser.previous)
		}

		if len(tokens) > 3 || len(tokens) == 2 {
			msg := fmt.Sprintf(MsgParseConstInvalidContent, constant.word)
			errorAt(&token, msg)
			ExitWithError(CodeParseError)
		} else if len(tokens) == 3 {
			left := tokens[0].value.(int)
			right := tokens[1].value.(int)

			switch tokens[2].typ {
			case TOKEN_PLUS: constant.value = left + right
			case TOKEN_STAR: constant.value = left * right
			}
		} else if len(tokens) == 1 {
			constant.value = tokens[0].value.(int)
		}

		consume(TOKEN_PAREN_CLOSE, MsgParseConstMissingCloseStmt)
	} else {
		advance()
		constant.value = parser.previous.value.(int)
	}

	return constant
}

func registerFunction(token Token) {
	var function Function

	function.internal = parser.internal
	function.ip = len(TheProgram.chunks)
	function.loc = token.loc
	function.parsed = false

	if !match(TOKEN_WORD) {
		errorAt(&token, MsgParseFunctionMissingName)
		ExitWithError(CodeParseError)
	}

	tokenWord := parser.previous
	function.name = tokenWord.value.(string)

	if function.name == "main" {
		for _, f := range TheProgram.chunks {
			if f.name == "main" {
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
		t := parser.previous

		if t.typ == TOKEN_DASH_DASH_DASH {
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
		for _, fc := range fcode.value.([]FunctionCall) {
			f := TheProgram.chunks[fc.ip]

			if reflect.DeepEqual(f.arguments, function.arguments) {
				msg := fmt.Sprintf(MsgParseArityArgumentSameSignatureError,
					GetRelativePath(f.loc.f), f.loc.l)
				errorAt(&tokenWord, msg)
				ExitWithError(CodeParseError)
			}

			if !reflect.DeepEqual(f.returns, function.returns) {
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

// Gets the initial token and the current offset. Returns the
// new Variable object and the new offset.
func newVariable(token Token, offset int) (Variable, int) {
	var newVar Variable
	var newOffset int
	const SIZE_64b = 8
	const SIZE_8b  = 1

	if !match(TOKEN_WORD) {
		errorAt(&token, MsgParseVarMissingWord)
		ExitWithError(CodeParseError)
	}

	newVar.word = parser.previous.value.(string)
	newVar.offset = offset
	// TODO: This should technically support bigger sizes for arrays
	newOffset = offset + SIZE_64b

	// TODO: Check for duplicated name

	advance()
	vt := parser.previous

	switch vt.typ {
	case TOKEN_BOOL:	newVar.dtype = DATA_BOOL
	case TOKEN_CHAR:	newVar.dtype = DATA_CHAR
	case TOKEN_INT:		newVar.dtype = DATA_INT
	case TOKEN_PTR:		newVar.dtype = DATA_PTR
	case TOKEN_STR:		newVar.dtype = DATA_STR
	default:
		errorAt(&parser.previous, MsgParseVarMissingValue)
		ExitWithError(CodeParseError)
	}

	return newVar, newOffset
}

/*    ___ ___  __  __ ___ ___ _      _ _____ ___ ___  _  _
 *   / __/ _ \|  \/  | _ \_ _| |    /_\_   _|_ _/ _ \| \| |
 *  | (_| (_) | |\/| |  _/| || |__ / _ \| |  | | (_) | .` |
 *   \___\___/|_|  |_|_| |___|____/_/ \_\_| |___\___/|_|\_|
 */
func takeFromFunctionCode(quant int) []Code {
	var result []Code
	codeLength := len(frontend.current.code)

	for index := codeLength-quant; index < codeLength; index++ {
		result = append(result, frontend.current.code[index])
	}

	frontend.current.code = frontend.current.code[:codeLength-quant]
	return result
}

func getBind(token Token) (Code, bool) {
	word := token.value.(string)

	for bindex, bind := range frontend.current.bindings.words {
		if bind == word {
			return Code{op: OP_PUSH_BIND, loc: token.loc, value: bindex}, true
		}
	}

	return Code{}, false
}

func getConstant(token Token) (Code, bool) {
	word := token.value.(string)

	if frontend.current != nil {
		for _, c := range frontend.current.constants {
			if c.word == word {
				return Code{
					op: OP_PUSH_INT,
					loc: token.loc,
					value: c.value,
				}, true
			}
		}
	}

	for _, c := range TheProgram.constants {
		if c.word == word {
			return Code{
				op: OP_PUSH_INT,
				loc: token.loc,
				value: c.value,
			}, true
		}
	}

	return Code{}, false
}

func getVariable(token Token) (Code, bool) {
	word := token.value.(string)

	if frontend.current != nil {
		for _, v := range frontend.current.variables {
			if v.word == word {
				return Code{
					op: OP_PUSH_VAR_LOCAL,
					loc: token.loc,
					value: v.offset,
				}, true
			}
		}
	}

	for _, v := range TheProgram.variables {
		if v.word == word {
			return Code{
				op: OP_PUSH_VAR_GLOBAL,
				loc: token.loc,
				value: v.offset,
			}, true
		}
	}

	return Code{}, false
}

func getFunction(token Token) (Code, bool) {
	var val []FunctionCall
	word := token.value.(string)

	for _, f := range TheProgram.chunks {
		if f.name == word {
			val = append(val, FunctionCall{name: f.name, ip: f.ip})
		}
	}

	if len(val) > 0 {
		return Code{op: OP_FUNCTION_CALL, loc: token.loc, value: val}, true
	}

	return Code{}, false
}

func expandWord(token Token) {
	b, bfound := getBind(token)

	if bfound {
		emit(b)
		return
	}

	v, vfound := getVariable(token)
	if vfound {
		emit(v)
		return
	}

	c, cfound := getConstant(token)

	if cfound {
		emit(c)
		return
	}

	// Find the word in functions. If it returns one, emit it
	code_f, ok_f := getFunction(token)

	if ok_f {
		emit(code_f)
		return
	}

	// If nothing has been found, emit the error.
	msg := fmt.Sprintf(MsgParseWordNotFound, token.value.(string))
	ReportErrorAtLocation(msg, token.loc)
	ExitWithError(CodeCodegenError)
}

func parseToken(token Token) {
	var code Code
	code.loc = token.loc
	code.value = token.value

	switch token.typ {
	// Constants
	case TOKEN_CONSTANT_CHAR:
		code.op = OP_PUSH_CHAR
		emit(code)
	case TOKEN_CONSTANT_FALSE:
		code.op = OP_PUSH_BOOL
		code.value = 0
		emit(code)
	case TOKEN_CONSTANT_INT:
		code.op = OP_PUSH_INT
		emit(code)
	case TOKEN_CONSTANT_STR:
		code.op = OP_PUSH_STR
		emit(code)
	case TOKEN_CONSTANT_TRUE:
		code.op = OP_PUSH_BOOL
		code.value = 1
		emit(code)
	case TOKEN_AMPERSAND:
		b, bfound := getBind(token)
		if bfound {
			code.op = OP_PUSH_BIND_ADDR
			code.value = b.value
			emit(code)
			return
		}
		v, vfound := getVariable(token)
		if vfound {
			switch v.op {
			case OP_PUSH_VAR_LOCAL: code.op = OP_PUSH_VAR_LOCAL_ADDR
			case OP_PUSH_VAR_GLOBAL: code.op = OP_PUSH_VAR_GLOBAL_ADDR
			}
			code.value = v.value
			emit(code)
		}

	// TYPE CASTING
	case TOKEN_BOOL:
		code.op = OP_CAST
		code.value = DATA_BOOL
		emit(code)
	case TOKEN_CHAR:
		code.op = OP_CAST
		code.value = DATA_CHAR
		emit(code)
	case TOKEN_INT:
		code.op = OP_CAST
		code.value = DATA_INT
		emit(code)
	case TOKEN_PTR:
		code.op = OP_CAST
		code.value = DATA_PTR
		emit(code)

	// DEFINITION
	case TOKEN_CONST:
		newConst := newConstant(token)
		frontend.current.constants = append(frontend.current.constants, newConst)
	case TOKEN_CURLY_BRACKET_OPEN:
		var tokens []Token

		if len(frontend.bodyStack) > 0 {
			errorAt(&token, "TODO: Cannot parse another body")
			ExitWithError(CodeParseError)
		}

		for !check(TOKEN_CURLY_BRACKET_CLOSE) && !check(TOKEN_EOF) {
			advance()
			tokens = append(tokens, parser.previous)
		}

		if len(tokens) == 0 {
			errorAt(&token, "TODO: error body cannot be empty")
			ExitWithError(CodeParseError)
		}

		consume(TOKEN_CURLY_BRACKET_CLOSE, "TODO: Missing curly bracket")
		frontend.bodyStack = tokens
	case TOKEN_VAR:
		newVar, newOffset := newVariable(token, frontend.current.localMemorySize)
		frontend.current.variables = append(frontend.current.variables, newVar)
		frontend.current.localMemorySize = newOffset

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
		body := frontend.bodyStack
		frontend.bodyStack = make([]Token, 0, 0)

		for i, t := range body {
			switch t.typ {
			case TOKEN_BRACKET_CLOSE:
				line = append(line, "]")
			case TOKEN_BRACKET_OPEN:
				line = append(line, "[")
			case TOKEN_CONSTANT_INT:
				line = append(line, strconv.Itoa(t.value.(int)))
			case TOKEN_WORD:
				word := t.value.(string)

				c, found := getConstant(t)

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
			word := parser.previous.value.(string)
			newWords = append(newWords, word)
		}

		consume(TOKEN_IN, MsgParseLetMissingIn)
		openScope(SCOPE_BIND, token)

		code.op = OP_LET_BIND
		code.value = bind(newWords)
		emit(code)
	case TOKEN_DONE:
		closeScopeAfterCheck(SCOPE_BIND)
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

	case TOKEN_AT:
		code.op = OP_LOAD
		emit(code)
	case TOKEN_C_AT:
		code.op = OP_LOAD_CHAR
		emit(code)
	case TOKEN_BANG:
		code.op = OP_STORE
		emit(code)
	case TOKEN_C_BANG:
		code.op = OP_STORE_CHAR
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

		c := openScope(SCOPE_LOOP, token)

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
		c := openScope(SCOPE_LOOP, token)
		_, indexN := getLimitIndexBindWord()
		emit(Code{op: OP_LET_BIND, loc: code.loc, value: bind([]string{indexN})})
		emit(Code{op: OP_LOOP_SETUP, loc: code.loc, value: c.ipStart})
		bc, _ := getBind(Token{loc: token.loc, value: indexN})
		emit(bc)
		emit(Code{op: OP_LOOP_START, loc: code.loc, value: c.ipStart})
	case TOKEN_LOOP:
		c := getCurrentScope()

		if c.typ != SCOPE_LOOP {
			// TODO: Improve error message, showing the starting and closing statements
			errorAt(&c.tokenStart, "TODO: ERROR MESSAGE")
			errorAt(&token, "TODO: ERROR MESSAGE")
			ExitWithError(CodeParseError)
		}

		switch c.tokenStart.typ {
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

		closeScopeAfterCheck(SCOPE_LOOP)
	case TOKEN_IF:
		c := openScope(SCOPE_IF, token)

		code.op = OP_IF_START
		code.value = c.ipStart
		emit(code)
	case TOKEN_FI:
		c := getCurrentScope()

		switch c.typ {
		case SCOPE_IF:
			code.op = OP_IF_ELSE
			code.value = c.ipStart
			emit(code)
			code.op = OP_IF_END
			emit(code)
			closeScopeAfterCheck(SCOPE_IF)
		case SCOPE_ELSE:
			code.op = OP_IF_END
			code.value = c.ipStart
			emit(code)
			closeScopeAfterCheck(SCOPE_ELSE)
		default:
			errorAt(&c.tokenStart, "TODO: ERROR MESSAGE")
			errorAt(&token, "TODO: ERROR MESSAGE")
			ExitWithError(CodeParseError)
		}
	case TOKEN_CASE:

	case TOKEN_ELSE:
		c := getCurrentScope()

		if c.typ != SCOPE_IF {
			errorAt(&c.tokenStart, "TODO: ERROR MESSAGE")
			errorAt(&token, "TODO: ERROR MESSAGE")
			ExitWithError(CodeParseError)
		}

		c.typ = SCOPE_ELSE
		code.op = OP_IF_ELSE
		code.value = c.ipStart
		emit(code)
	}
}

func parseArityInAssembly(token Token, args *Arity) {
	var newArg Argument

	switch token.typ {
	case TOKEN_BOOL:
		newArg.typ = DATA_BOOL
	case TOKEN_CHAR:
		newArg.typ = DATA_CHAR
	case TOKEN_INT:
		newArg.typ = DATA_INT
	case TOKEN_PTR:
		newArg.typ = DATA_PTR
	case TOKEN_STR:
		newArg.typ = DATA_STR
	default:
		msg := fmt.Sprintf(MsgParseTypeUnknown, token.value.(string))
		errorAt(&token, msg)
		ExitWithError(CodeParseError)
	}

	args.types = append(args.types, newArg)
}

func parseArityInFunction(token Token, function *Function, parsingArguments bool) {
	var newArg Argument

	switch token.typ {
	case TOKEN_ANY:
		if !parser.internal {
			errorAt(&token, MsgParseArityArgumentAnyOnlyInternal)
			ExitWithError(CodeParseError)
		}

		newArg.typ = DATA_ANY
	case TOKEN_BOOL:
		newArg.typ = DATA_BOOL
	case TOKEN_CHAR:
		newArg.typ = DATA_CHAR
	case TOKEN_INT:
		newArg.typ = DATA_INT
	case TOKEN_PTR:
		newArg.typ = DATA_PTR
	case TOKEN_STR:
		newArg.typ = DATA_STR
	case TOKEN_PARAPOLY:
		if !parsingArguments {
			errorAt(&token, MsgParseArityReturnParapolyNotAllowed)
			ExitWithError(CodeParseError)
		}

		newArg.typ = DATA_INFER
		newArg.name = token.value.(string)
		function.arguments.parapoly = true
	case TOKEN_WORD:
		w := token.value.(string)

		if parsingArguments {
			msg := fmt.Sprintf(MsgParseTypeUnknown, w)
			errorAt(&token, msg)
			ExitWithError(CodeParseError)
		}

		funcArgs := function.arguments
		argTest := Argument{name: w, typ: DATA_INFER}

		if funcArgs.parapoly && Contains(funcArgs.types, argTest) {
			newArg.typ = DATA_INFER
			newArg.name = w
			function.returns.parapoly = true
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
		function.returns.types = append(function.returns.types, newArg)
	}
}

func parseFunction(token Token) {
	// Recreate a temporary function entry to match with the already registered
	// functions in TheProgram. That's why this step doesn't have any error checking.
	var testFunc Function

	advance()
	testFunc.name = parser.previous.value.(string)
	advance()

	parsingArguments := true

	for !match(TOKEN_PAREN_CLOSE) {
		advance()
		t := parser.previous

		if t.typ == TOKEN_DASH_DASH_DASH {
			parsingArguments = false
			continue
		}

		parseArityInFunction(t, &testFunc, parsingArguments)
	}

	for index, f := range TheProgram.chunks {
		if !f.parsed && f.name == testFunc.name &&
			reflect.DeepEqual(f.arguments, testFunc.arguments) {
			frontend.current = &TheProgram.chunks[index]
			break
		}
	}

	if frontend.current != nil {
		for !match(TOKEN_RET) {
			advance()
			parseToken(parser.previous)
		}

		emitReturn()

		// Marking the function as "parsed", then clearing out the bindings, and
		// removing the pointer to this function, so we can safely check for the next one.
		frontend.current.parsed = true
		frontend.current = nil
	} else {
		// This would be a catastrophic issue. Since we already registered functions,
		// there's no way we don't find a function with the same name that has not been
		// parsed yet. Since we can't recover from this error, we must exit.
		msg := fmt.Sprintf(MsgParseFunctionSignatureNotFound, testFunc.name)
		errorAt(&parser.previous, msg)
		ExitWithError(CodeParseError)
	}
}

/*
 * Compilation: First Pass
 *   This step goes through the files and check for the TOKEN_USING, adding those
 *   files to the compilation queue.
 */
func compilationFirstPass(index int) {
	f := file.files[index]

	startParser(f)

	for !check(TOKEN_EOF) {
		advance()
		token := parser.previous

		if token.typ == TOKEN_USING {
			advance()

			if parser.previous.typ != TOKEN_WORD {
				errorAt(&parser.previous, "TODO: ERROR USING")
				ExitWithError(CodeParseError)
			}

			file.Open(parser.previous.value.(string))
		}
	}
}

/*
 * Compilation: Second Pass
 *   The second step registers the words the program will use.
 */
func compilationSecondPass(index int) {
	f := file.files[index]

	startParser(f)

	for !check(TOKEN_EOF) {
		advance()
		token := parser.previous

		switch token.typ {
		// The second pass will care about the following tokens:
		case TOKEN_CONST:
			newConst := newConstant(token)
			TheProgram.constants = append(TheProgram.constants, newConst)
		case TOKEN_VAR:
			newVar, newOffset := newVariable(token, TheProgram.staticMemorySize)
			TheProgram.variables = append(TheProgram.variables, newVar)
			TheProgram.staticMemorySize = newOffset

		case TOKEN_FN: registerFunction(token)

		// But it needs to do nothing when it sees the followings:
		//   TOKEN_USING: advance over the string, then continue back to the loop.
		case TOKEN_USING:
			advance()
			continue

		// Now, if it matches with something else, then error.
		default:
			ReportErrorAtLocation(MsgParseErrorProgramScope, token.loc)
			ExitWithError(CodeParseError)
		}
	}
}

/*
 * Compilation: Third Pass
 *   The third step goes through each function and compiles the code for each one
 *   of them. Register and make all the OP codes for these functions.
 */
func compilationThirdPass(index int) {
	f := file.files[index]

	startParser(f)

	for !check(TOKEN_EOF) {
		advance()
		token := parser.previous

		if token.typ == TOKEN_FN {
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

	for index := 0; index < len(file.files); index++ {
		compilationThirdPass(index)
	}

	if frontend.error {
		ExitWithError(CodeParseError)
	}
}
