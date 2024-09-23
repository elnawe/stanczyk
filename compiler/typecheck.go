package skc

import (
	"fmt"
)

const STACK_SIZE = 10

type Typecheck struct {
	stack      [STACK_SIZE]DataType
	stackCount int
	scope      int
}

var tc Typecheck
var snapshots [10]Typecheck

func getStackValues() string {
	r := ""

	for index := 0; index < tc.stackCount; index++ {
		r += getDataTypeName(tc.stack[index])

		if (index != tc.stackCount - 1) {
			r += " "
		}
	}

	return r
}

func getOperationName(code Code) string {
	name := "Unhandled"
	switch code.op {
	case OP_ADD: name = "+ (add)"
	case OP_ARGC: name = "argc"
	case OP_ARGV: name = "argv"
	case OP_BIND: name = "bind"
	case OP_CAST: name = "cast to " + getDataTypeName(code.value.(DataType))
	case OP_DIVIDE: name = "div"
	case OP_DROP: name = "drop"
	case OP_DUP: name = "dup"
	case OP_EQUAL: name = "= (equal)"
	case OP_EXTERN: name = "extern"
	case OP_GREATER: name = "> (greater)"
	case OP_GREATER_EQUAL: name = ">= (greater equal)"
	case OP_JUMP: name = "else"
	case OP_JUMP_IF_FALSE: name = "do"
	case OP_LESS: name = "< (less)"
	case OP_LESS_EQUAL: name = "<= (less equal)"
	case OP_LOAD8, OP_LOAD16, OP_LOAD32, OP_LOAD64: name = "load"
	case OP_LOOP: name = "loop"
	case OP_MULTIPLY: name = "* (multiply)"
	case OP_NOT_EQUAL: name = "!= (not equal)"
	case OP_OVER: name = "over"
	case OP_RET: name = "ret"
	case OP_STORE8, OP_STORE16, OP_STORE32, OP_STORE64: name = "store"
	case OP_SUBSTRACT: name = "- (substract)"
	case OP_SWAP: name = "swap"
	case OP_TAKE: name = "take"
	case OP_WORD: name = code.value.(string)
	}

	return name
}

func getDataTypeName(v DataType) string {
	r := ""
	switch v {
	case DATA_EMPTY: r = ""
	case DATA_BOOL:  r = "bool"
	case DATA_CHAR:  r = "char"
	case DATA_INT:	 r = "int"
	case DATA_PTR:   r = "ptr"
	case DATA_ANY:   r = "any"
	}
	return r
}

func getDataTypeNames(dt []DataType) string {
	r := ""

	for i, v := range dt {
		r += getDataTypeName(v)
		if i != len(dt) -1 && v != DATA_EMPTY {
			r += " "
		}
	}

	return r
}

func assertArgumentTypes(test []DataType, want [][]DataType, code Code, loc Location) {
	var errFound []bool

	for _, w := range want {
		err := false

		for i, t := range test {
			if w[i] == DATA_ANY {
				if t == DATA_EMPTY {
					err = true
					break
				}
			} else {
				if w[i] != t && t != DATA_ANY {
					err = true
					break
				}
			}
		}

		errFound = append(errFound, err)
	}

	if !Contains(errFound, false) {
		wantsText := ""

		for i, w := range want {
			wantsText += "(" + getDataTypeNames(w) + ")"

			if i != len(want) - 1 {
				wantsText += " or "
			}
		}

		msg := fmt.Sprintf(MsgTypecheckArgumentsTypesMismatch,
			getOperationName(code), getDataTypeNames(test), wantsText)
		ReportErrorAtLocation(msg, loc)
		ExitWithError(CodeTypecheckError)
	}
}

func assertArgumentType(test []DataType, want []DataType, code Code, loc Location) {
	errFound := false

	for i, t := range test {
		if want[i] == DATA_ANY {
			if t == DATA_EMPTY {
				errFound = true
				break
			}
		} else {
			if want[i] != t && t != DATA_ANY {
				errFound = true
				break
			}
		}
	}

	if errFound {
		msg := fmt.Sprintf(MsgTypecheckArgumentsTypeMismatch,
			getOperationName(code), getDataTypeNames(test), getDataTypeNames(want))
		ReportErrorAtLocation(msg, loc)
		ExitWithError(CodeTypecheckError)
	}
}

func (this *Typecheck) reset() {
	this.stack = [STACK_SIZE]DataType{}
	this.stackCount = 0
}

func (this *Typecheck) push(t DataType) {
	this.stack[this.stackCount] = t
	this.stackCount++
}

func (this *Typecheck) pop() DataType {
	if this.stackCount == 0 {
		return DATA_EMPTY
	}
	this.stackCount--
	v := this.stack[this.stackCount]
	this.stack[this.stackCount] = DATA_EMPTY
	return v
}

func dtArray(values ...DataType) []DataType {
	var r []DataType
	for _, t := range values {
		r = append(r, t)
	}
	return r
}

func TypecheckRun() {
	mainHandled := false

	for ifunction, function := range TheProgram.chunks {
		var binds []DataType
		if function.name == "main" {
			mainHandled = true
			if len(function.args) > 0 || len(function.rets) > 0 {
				ReportErrorAtLocation(MsgTypecheckMainFunctionNoArgumentsOrReturn, function.loc)
				ExitWithError(CodeTypecheckError)
			}
		}

		expectedReturnCount := len(function.rets)

		for _, dt := range function.args {
			tc.push(dt)
		}

		for icode, code := range function.code {
			instruction := code.op
			loc := code.loc

			switch instruction {
			// Constants
			case OP_PUSH_BOOL:
				tc.push(DATA_BOOL)
			case OP_PUSH_BOUND:
				value := code.value.(Bound)
				tc.push(binds[value.id])
			case OP_PUSH_CHAR:
				tc.push(DATA_CHAR)
			case OP_PUSH_INT:
				tc.push(DATA_INT)
			case OP_PUSH_PTR:
				tc.push(DATA_PTR)
			case OP_PUSH_STR:
				tc.push(DATA_PTR)

			// Intrinsics
			case OP_ADD, OP_SUBSTRACT:
				allowedTypes := [][]DataType{
					dtArray(DATA_INT, DATA_INT),
					dtArray(DATA_PTR, DATA_INT),
				}
				b := tc.pop()
				a := tc.pop()
				assertArgumentTypes(dtArray(a, b), allowedTypes, code, loc)
				if a == DATA_INT && b == DATA_INT {
					tc.push(DATA_INT)
				} else {
					tc.push(DATA_PTR)
				}
			case OP_ARGC:
				tc.push(DATA_INT)
			case OP_ARGV:
				tc.push(DATA_PTR)
			case OP_BIND:
				var have []DataType
				var wants []DataType
				value := code.value.(int)

				for index := len(binds); index < value; index++ {
					a := tc.pop()
					binds = append([]DataType{a}, binds...)
					have = append([]DataType{a}, have...)
					wants = append(wants, DATA_ANY)
				}
				assertArgumentType(have, wants, code, loc)
			case OP_CAST:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(DATA_ANY), code, loc)
				tc.push(code.value.(DataType))
			case OP_DIVIDE:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(DATA_INT, DATA_INT), code, loc)
				tc.push(DATA_INT)
				tc.push(DATA_INT)
			case OP_DROP:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(DATA_ANY), code, loc)
			case OP_DUP:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(DATA_ANY), code, loc)
				tc.push(a)
				tc.push(a)
			case OP_EQUAL, OP_NOT_EQUAL, OP_GREATER, OP_GREATER_EQUAL, OP_LESS, OP_LESS_EQUAL:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(DATA_ANY, DATA_ANY), code, loc)
				tc.push(DATA_BOOL)
			case OP_EXTERN:
				var have []DataType
				value := code.value.(Extern)

				for range value.args {
					t := tc.pop()
					have = append([]DataType{t}, have...)
				}

				assertArgumentType(have, value.args, code, loc)

				for _, dt := range value.rets {
					tc.push(dt)
				}
			case OP_JUMP_IF_FALSE:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(DATA_BOOL), code, loc)
				tc.scope++
				snapshots[tc.scope] = tc
			case OP_LOAD8, OP_LOAD16, OP_LOAD32, OP_LOAD64:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(DATA_PTR), code, loc)
				tc.push(DATA_PTR)
			case OP_MULTIPLY:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(DATA_INT, DATA_INT), code, loc)
				tc.push(DATA_INT)
			case OP_OVER:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(DATA_ANY, DATA_ANY), code, loc)
				tc.push(a)
				tc.push(b)
				tc.push(a)
			case OP_ROTATE:
				c := tc.pop()
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b, c),
					dtArray(DATA_ANY, DATA_ANY, DATA_ANY), code, loc)
				tc.push(b)
				tc.push(c)
				tc.push(a)
			case OP_STORE8, OP_STORE16, OP_STORE32, OP_STORE64:
				allowedTypes := [][]DataType{
					dtArray(DATA_PTR, DATA_PTR),
					dtArray(DATA_PTR, DATA_CHAR),
				}
				b := tc.pop()
				a := tc.pop()
				assertArgumentTypes(dtArray(a, b), allowedTypes, code, loc)
			case OP_SWAP:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(DATA_ANY, DATA_ANY), code, loc)
				tc.push(b)
				tc.push(a)
			case OP_TAKE:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(DATA_ANY), code, loc)
				tc.push(a)

			case OP_END_IF, OP_END_LOOP:
				if snapshots[tc.scope].stackCount != tc.stackCount {
					ReportErrorAtLocation(MsgsTypecheckStackSizeChangedAfterBlock, loc)
					ExitWithError(CodeTypecheckError)
				}
				if snapshots[tc.scope].stack != tc.stack {
					ReportErrorAtLocation(MsgsTypecheckStackTypeChangedAfterBlock, loc)
					ExitWithError(CodeTypecheckError)
				}
				tc.scope--

			// Special
			case OP_WORD:
				var have []DataType
				var fnCall Function
				fns := FindFunctionsByName(code)

				if len(fns) == 1 {
					fnCall = fns[0]
				} else {
					paramsMsg := ""
					for index, f := range fns {
						if index > 0 {
							paramsMsg += " or "
						}

						paramsMsg += "(" + getDataTypeNames(f.args) + ")"

						lastInStack := tc.stackCount - len(f.args)
					    stackCopy := tc.stack[lastInStack:]
						found := false
						for i, _ := range f.args {
							if f.args[i] != stackCopy[i] {
								found = false
								break
							}

							found = true
						}

						if found {
							fnCall = f
							break
						}
					}

					if !fnCall.called {
						msg := fmt.Sprintf(MsgTypecheckFunctionPolymorphicMatchNotFound, code.value, getStackValues(), paramsMsg)
						ReportErrorAtLocation(msg, function.loc)
						ExitWithError(CodeTypecheckError)
					}
				}

				ChangeValueOfFunction(ifunction, icode,
					FunctionCall{name: fnCall.name, ip: fnCall.ip})

				for range fnCall.args {
					t := tc.pop()
					have = append([]DataType{t}, have...)
				}

				assertArgumentType(have, fnCall.args, code, loc)

				for _, dt := range fnCall.rets {
					tc.push(dt)
				}

			case OP_JUMP, OP_LOOP, OP_RET:

			default:
				fmt.Println("Unhandled", getOperationName(code))
			}
		}

		if tc.stackCount != expectedReturnCount {
			msg := fmt.Sprintf(MsgTypecheckNotExplicitlyReturned,
				function.name, getStackValues())
			ReportErrorAtEOF(msg)
			ExitWithError(CodeTypecheckError)
		}

		tc.reset()
	}

	if !mainHandled {
		ReportErrorAtEOF(MsgTypecheckMissingEntryPoint)
		ExitWithError(CodeTypecheckError)
	}
}
