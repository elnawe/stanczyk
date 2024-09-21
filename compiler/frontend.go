package skc

import (
	"fmt"
)

type ScopeName int

const (
	SCOPE_PROGRAM ScopeName = iota
	SCOPE_FUNCTION
)

type Object struct {
	id    int
	value int
	word  string
}

type Scope struct {
	tt     TokenType
	thenIP int
	loopIP int
}

type Frontend struct {
	bindings  []Bound
	constants []Object
	memories  []Object
	current	  *Function
	error     bool
	sLevel    int
	sName     ScopeName
	scope     [10]Scope
	words     []string
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
	result := tt == parser.current.typ
	return result
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
func newConstant(token Token) {
	var constant Object
	var tokens []Token

	if !match(TOKEN_WORD) {
		errorAt(&parser.previous, MsgParseConstMissingWord)
		return
	}

	constant.id = len(frontend.constants)
	constant.word = parser.previous.value.(string)

	for _, c := range frontend.constants {
		if c.word == constant.word {
			msg := fmt.Sprintf(MsgParseConstOverrideNotAllowed, constant.word)
			errorAt(&parser.previous, msg)
			return
		}
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
			return
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

		consume(TOKEN_PAREN_CLOSE, MsgParseConstMissingDot)
	} else {
		advance()
		constant.value = parser.previous.value.(int)
	}

	frontend.constants = append(frontend.constants, constant)
}

func newFunction(token Token) {
	var function Function
	function.polymorphic = token.typ == TOKEN_FN_STAR
	function.ip = len(TheProgram.chunks)
	function.loc = token.loc
	function.internal = parser.internal
	frontend.current = &function

	if !match(TOKEN_WORD) {
		errorAt(&token, MsgParseFunctionMissingName)
		ExitWithError(CodeParseError)
	}

	word := parser.previous
	name := word.value.(string)

	function.name = name
	if name == "main" {
		function.called = true
		for _, f := range TheProgram.chunks {
			if f.name == "main" {
				msg := fmt.Sprintf(MsgParseFunctionMainAlreadyDefined, f.loc.f, f.loc.l)
				errorAt(&token, msg)
				ExitWithError(CodeParseError)
			}
		}
	}


	for _, f := range TheProgram.chunks {
		if f.name == function.name && (!f.polymorphic || !function.polymorphic) {
			msg := fmt.Sprintf(MsgParseFunctionNotPolymorphic, function.name)
			var loc Location

			if !f.polymorphic {
				loc = f.loc
			} else {
				loc = token.loc
			}

			ReportErrorAtLocation(msg, loc)
			ExitWithError(CodeParseError)
		}
	}

	if !check(TOKEN_RIGHT_ARROW) && !check(TOKEN_PAREN_OPEN) {
		for !check(TOKEN_RIGHT_ARROW) && !check(TOKEN_PAREN_OPEN) && !check(TOKEN_EOF) {
			advance()
			t := parser.previous
			targ := DATA_EMPTY

			switch t.typ {
			case TOKEN_DTYPE_BOOL: targ = DATA_BOOL
			case TOKEN_DTYPE_CHAR: targ = DATA_CHAR
			case TOKEN_DTYPE_INT:  targ = DATA_INT
			case TOKEN_DTYPE_PTR:  targ = DATA_PTR
			default:
				msg := fmt.Sprintf(MsgParseFunctionUnknownType, t.value)
				errorAt(&t, msg)
				ExitWithError(CodeParseError)
			}

			function.args = append(function.args, targ)
		}
	}

	if match(TOKEN_RIGHT_ARROW) {
		if check(TOKEN_PAREN_OPEN) {
			errorAt(&parser.previous, MsgParseFunctionNoReturnSpecified)
		}

		for !check(TOKEN_PAREN_OPEN) {
			advance()
			t := parser.previous
			tret := DATA_EMPTY

			switch t.typ {
			case TOKEN_DTYPE_BOOL: tret = DATA_BOOL
			case TOKEN_DTYPE_CHAR: tret = DATA_CHAR
			case TOKEN_DTYPE_INT: tret = DATA_INT
			case TOKEN_DTYPE_PTR: tret = DATA_PTR
			default:
				msg := fmt.Sprintf(MsgParseFunctionUnknownType, t.value)
				errorAt(&t, msg)
				ExitWithError(CodeParseError)
			}

			function.rets = append(function.rets, tret)
		}
	}

	consume(TOKEN_PAREN_OPEN, MsgParseFunctionMissingDo)

	frontend.sLevel++
	frontend.scope[1].tt = TOKEN_FN

	for frontend.sLevel > 0 && !check(TOKEN_EOF) {
		advance()
		parseToken(parser.previous)
	}

	emitReturn()

	TheProgram.chunks = append(TheProgram.chunks, function)
	frontend.bindings = make([]Bound, 0, 0)
}

func newReserve(token Token) {
	var memory Object
	if !match(TOKEN_WORD) {
		errorAt(&token, MsgParseReserveMissingWord)
		ExitWithError(CodeParseError)
	}
	memory.id = len(frontend.memories)
	memory.word = parser.previous.value.(string)

	for _, m := range frontend.memories {
		if m.word == memory.word {
			msg := fmt.Sprintf(MsgParseReserveOverrideNotAllowed, memory.word)
			errorAt(&parser.previous, msg)
			ExitWithError(CodeParseError)
		}
	}

	advance()
	vt := parser.previous

	switch vt.typ {
	case TOKEN_WORD:
		found := false
		for _, c := range frontend.constants {
			if c.word == vt.value {
				found = true
				memory.value = c.value
				break
			}
		}

		if !found {
			msg := fmt.Sprintf(MsgParseReserveValueIsNotConst, vt.value)
			errorAt(&vt, msg)
			ExitWithError(CodeParseError)
		}
	case TOKEN_INT:
		memory.value = vt.value.(int)
	default:
		errorAt(&parser.previous, MsgParseReserveMissingValue)
		ExitWithError(CodeParseError)
	}

	frontend.memories = append(frontend.memories, memory)
}

func compile(index int) {
	f := file.files[index]

	startParser(f)

	for !check(TOKEN_EOF) {
		advance()
		token := parser.previous
		switch token.typ {
		case TOKEN_CONST:
			newConstant(token)
		case TOKEN_FN, TOKEN_FN_STAR:
			newFunction(token)
		case TOKEN_RESERVE:
			newReserve(token)
		case TOKEN_USING:
			advance()
			file.Open(parser.previous.value.(string))
		default:
			ReportErrorAtLocation(MsgParseErrorProgramScope, token.loc)
			ExitWithError(CodeParseError)
		}
	}
}

/*    ___ ___  __  __ ___ ___ _      _ _____ ___ ___  _  _
 *   / __/ _ \|  \/  | _ \_ _| |    /_\_   _|_ _/ _ \| \| |
 *  | (_| (_) | |\/| |  _/| || |__ / _ \| |  | | (_) | .` |
 *   \___\___/|_|  |_|_| |___|____/_/ \_\_| |___\___/|_|\_|
 */
func expandWord(token Token) {
	if !parser.internal {
		addWord(token.value.(string))
	}
	word := token.value

	for _, b := range frontend.bindings {
		if word == b.word {
			emit(Code{op: OP_PUSH_BOUND, loc: token.loc, value: b})
			return
		}
	}

	for _, c := range frontend.constants {
		if c.word == word {
			emit(Code{op: OP_PUSH_INT, loc: token.loc, value: c.value})
			return
		}
	}

	for _, m := range frontend.memories {
		if m.word == word {
			emit(Code{op: OP_PUSH_PTR, loc: token.loc, value: m})
			return
		}
	}

	emit(Code{op: OP_WORD, loc: token.loc, value: word})
}

func addWord(word string) {
	for _, w := range frontend.words {
		if w == word {
			return
		}
	}
	frontend.words = append(frontend.words, word)
}

func addBind(token Token) {
	startingBoundIndex := len(frontend.bindings)

	consume(TOKEN_PAREN_OPEN, MsgParseBindMissingOpenStmt)

	for match(TOKEN_WORD) {
		t := parser.previous
		frontend.bindings = append(frontend.bindings, Bound{
			word: t.value.(string),
			id: len(frontend.bindings),
		})
	}

	if len(frontend.bindings) == startingBoundIndex {
		errorAt(&token, MsgParseBindEmptyBody)
		for !match(TOKEN_PAREN_CLOSE) { advance() }
		return
	}

	consume(TOKEN_PAREN_CLOSE, MsgParseBindMissingCloseStmt)
	emit(Code{op: OP_BIND, loc: token.loc, value: len(frontend.bindings)})
}

func newSyscall(token Token) {
	var value []DataType
	var code Code
	code.op = OP_SYSCALL
	code.loc = token.loc

	consume(TOKEN_PAREN_OPEN, MsgParseSyscallMissingOpenStmt)

	for !check(TOKEN_PAREN_CLOSE) && !check(TOKEN_EOF) {
		advance()
		var arg DataType
		t := parser.previous

		switch t.typ {
		case TOKEN_DTYPE_BOOL: arg = DATA_BOOL
		case TOKEN_DTYPE_CHAR: arg = DATA_CHAR
		case TOKEN_DTYPE_INT:  arg = DATA_INT
		case TOKEN_DTYPE_PTR:  arg = DATA_PTR
		default:
			msg := fmt.Sprintf(MsgParseFunctionUnknownType, t.value)
			errorAt(&t, msg)
			ExitWithError(CodeParseError)
		}

		value = append(value, arg)
	}
	code.value = value
	consume(TOKEN_PAREN_CLOSE, MsgParseSyscallMissingCloseStmt)
	emit(code)
}

func parseToken(token Token) {
	var code Code
	code.loc = token.loc
	code.value = token.value
	sLevel := &frontend.sLevel

	switch token.typ {
	// Constants
	case TOKEN_CHAR:
		code.op = OP_PUSH_CHAR
		emit(code)
	case TOKEN_FALSE:
		code.op = OP_PUSH_BOOL
		code.value = 0
		emit(code)
	case TOKEN_INT:
		code.op = OP_PUSH_INT
		emit(code)
	case TOKEN_STR:
		code.op = OP_PUSH_STR
		emit(code)
	case TOKEN_TRUE:
		code.op = OP_PUSH_BOOL
		code.value = 1
		emit(code)

	// Intrinsics
	case TOKEN_ARGC:
		code.op = OP_ARGC
		emit(code)
	case TOKEN_ARGV:
		code.op = OP_ARGV
		emit(code)
	case TOKEN_BANG_EQUAL:
		code.op = OP_NOT_EQUAL
		emit(code)
	case TOKEN_BIND:
		addBind(token)
	case TOKEN_CAST_BOOL:
		code.op = OP_CAST
		code.value = DATA_BOOL
		emit(code)
	case TOKEN_CAST_CHAR:
		code.op = OP_CAST
		code.value = DATA_CHAR
		emit(code)
	case TOKEN_CAST_INT:
		code.op = OP_CAST
		code.value = DATA_INT
		emit(code)
	case TOKEN_CAST_PTR:
		code.op = OP_CAST
		code.value = DATA_PTR
		emit(code)
	case TOKEN_DIV:
		code.op = OP_DIVIDE
		emit(code)
	case TOKEN_DROP:
		code.op = OP_DROP
		emit(code)
	case TOKEN_DUP:
		code.op = OP_DUP
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
	case TOKEN_LESS:
		code.op = OP_LESS
		emit(code)
	case TOKEN_LESS_EQUAL:
		code.op = OP_LESS_EQUAL
		emit(code)
	case TOKEN_LOAD8:
		code.op = OP_LOAD8
		emit(code)
	case TOKEN_LOAD16:
		code.op = OP_LOAD16
		emit(code)
	case TOKEN_LOAD32:
		code.op = OP_LOAD32
		emit(code)
	case TOKEN_LOAD64:
		code.op = OP_LOAD64
		emit(code)
	case TOKEN_MINUS:
		code.op = OP_SUBSTRACT
		emit(code)
	case TOKEN_OVER:
		code.op = OP_OVER
		emit(code)
	case TOKEN_PLUS:
		code.op = OP_ADD
		emit(code)
	case TOKEN_RET:
		code.op = OP_RET
		code.value = 0
		emit(code)
	case TOKEN_ROTATE:
		code.op = OP_ROTATE
		emit(code)
	case TOKEN_STAR:
		code.op = OP_MULTIPLY
		emit(code)
	case TOKEN_STORE8:
		code.op = OP_STORE8
		emit(code)
	case TOKEN_STORE16:
		code.op = OP_STORE16
		emit(code)
	case TOKEN_STORE32:
		code.op = OP_STORE32
		emit(code)
	case TOKEN_STORE64:
		code.op = OP_STORE64
		emit(code)
	case TOKEN_SWAP:
		code.op = OP_SWAP
		emit(code)
	case TOKEN_SYSCALL:
		newSyscall(token)
	case TOKEN_TAKE:
		code.op = OP_TAKE
		emit(code)
	case TOKEN_THIS:
		loc := code.loc
		code.op = OP_PUSH_STR
		code.value = fmt.Sprintf("%s:%d:%d", loc.f, loc.l, loc.c)
		emit(code)

	// Special
	case TOKEN_WORD:
		expandWord(token)
	case TOKEN_IF:
		*sLevel++
		frontend.scope[*sLevel].tt = token.typ
	case TOKEN_ELSE:
		if *sLevel > 0 {
			prevThen := frontend.scope[*sLevel].thenIP
			frontend.scope[*sLevel].thenIP = len(frontend.current.code)
			code.op = OP_JUMP
			emit(code)
			frontend.current.code[prevThen].value = len(frontend.current.code)
		} else {
			errorAt(&token, MsgParseElseOrphanTokenFound)
		}
	case TOKEN_LOOP:
		*sLevel++
		frontend.scope[*sLevel].tt = token.typ
		frontend.scope[*sLevel].loopIP = len(frontend.current.code)
	case TOKEN_PAREN_OPEN:
		if *sLevel > 0 {
			frontend.scope[*sLevel].thenIP = len(frontend.current.code)
			code.op = OP_JUMP_IF_FALSE
			emit(code)
		} else {
			errorAt(&token, MsgParseDoOrphanTokenFound)
		}
	case TOKEN_PAREN_CLOSE:
		if *sLevel > 0 {
			cScope := frontend.scope[*sLevel]

			switch cScope.tt {
			case TOKEN_IF:
				code.op = OP_END_IF
				emit(code)
				frontend.current.code[cScope.thenIP].value = len(frontend.current.code)
			case TOKEN_LOOP:
				code.op = OP_LOOP
				code.value = cScope.loopIP
				emit(code)

				var endLoop Code
				endLoop.loc = token.loc
				endLoop.op = OP_END_LOOP
				emit(endLoop)
				frontend.current.code[cScope.thenIP].value = len(frontend.current.code)
			}

			*sLevel--
		} else {
			errorAt(&token, MsgParseDotOrphanTokenFound)
		}
	}
}

func markFunctionsAsCalled() {
	for x := 0; x < len(frontend.words); x++ {
		word := frontend.words[x]

		for y := 0; y < len(TheProgram.chunks); y++ {
			f := &TheProgram.chunks[y]

			if f.name == word {
				f.called = true

				for _, code := range f.code {
					if code.op == OP_WORD {
						addWord(code.value.(string))
					}
				}
			}
		}
	}
}

func FrontendRun() {
	// Core standard library
	file.Open("basics")

	// User entry file
	file.Open(Stanczyk.workspace.entry)

	for index := 0; index < len(file.files); index++ {
		compile(index)
	}

	markFunctionsAsCalled()

	TheProgram.memories = frontend.memories

	if frontend.error {
		ExitWithError(CodeParseError)
	}
}
