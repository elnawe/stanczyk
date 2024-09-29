package skc

import (
	"fmt"
	"reflect"
)

const STACK_SIZE = 10

type Typecheck struct {
	stack       [STACK_SIZE]DataType
	stackCount  int
	scope       int
}

type DeadCodeElim struct {
	funcsCalled []int
}

var tc Typecheck
var snapshots [10]Typecheck
var dce DeadCodeElim

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
	case OP_ASSEMBLY: name = "asm"
	case OP_BIND: name = "bind"
	case OP_CAST: name = "cast to " + getDataTypeName(code.value.(DataType))
	case OP_DIVIDE: name = "div"
	case OP_EQUAL: name = "= (equal)"
	case OP_FUNCTION_CALL: name = "function: " + code.value.([]FunctionCall)[0].name
	case OP_GREATER: name = "> (greater)"
	case OP_GREATER_EQUAL: name = ">= (greater equal)"
	case OP_JUMP: name = "else"
	case OP_JUMP_IF_FALSE: name = "then"
	case OP_LESS: name = "< (less)"
	case OP_LESS_EQUAL: name = "<= (less equal)"
	case OP_LOAD8, OP_LOAD16, OP_LOAD32, OP_LOAD64: name = "load"
	case OP_LOOP: name = "loop"
	case OP_MULTIPLY: name = "* (multiply)"
	case OP_NOT_EQUAL: name = "!= (not equal)"
	case OP_RET: name = "ret"
	case OP_STORE8, OP_STORE16, OP_STORE32, OP_STORE64: name = "store"
	case OP_SUBSTRACT: name = "- (substract)"
	case OP_TAKE: name = "take"
	}

	return name
}

func getDataTypeName(v DataType) string {
	r := ""
	switch v {
	case DATA_NONE:  r = ""
	case DATA_BOOL:  r = "bool"
	case DATA_CHAR:  r = "char"
	case DATA_INFER: r = "$type"
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
		if i != len(dt) -1 && v != DATA_NONE {
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
				if t == DATA_NONE {
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
		if want[i] == DATA_ANY || want[i] == DATA_INFER {
			if t == DATA_NONE {
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

func dtArray(values ...DataType) []DataType {
	var r []DataType
	for _, t := range values {
		r = append(r, t)
	}
	return r
}

func findFunctionByIP(ip int) Function {
	return TheProgram.chunks[ip]
}

func (this *DeadCodeElim) push(i int) {
	this.funcsCalled = append(this.funcsCalled, i)
}

func (this *DeadCodeElim) pop() int {
	var x int
	x = this.funcsCalled[len(this.funcsCalled) - 1]
	this.funcsCalled = this.funcsCalled[:len(this.funcsCalled) - 1]
	return x
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
		return DATA_NONE
	}
	this.stackCount--
	v := this.stack[this.stackCount]
	this.stack[this.stackCount] = DATA_NONE
	return v
}

func ValidateRun() {
	mainHandled := false

	for ifunction, function := range TheProgram.chunks {
		var binds []DataType
		argumentTypes := function.arguments.types
		returnTypes := function.returns.types


		if function.name == "main" {
			mainHandled = true
			dce.push(function.ip)

			if len(argumentTypes) > 0 || len(returnTypes) > 0 {
				ReportErrorAtLocation(
					MsgTypecheckMainFunctionNoArgumentsOrReturn,
					function.loc,
				)
				ExitWithError(CodeTypecheckError)
			}
		}

		expectedReturnCount := len(returnTypes)

		for _, t := range argumentTypes {
			tc.push(t.typ)
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
			case OP_ASSEMBLY:
				var have []DataType
				var want []DataType
				value := code.value.(Assembly)

				for _, d := range value.arguments.types {
					t := tc.pop()
					have = append([]DataType{t}, have...)
					want = append(want, d.typ)
				}

				assertArgumentType(have, want, code, loc)

				for _, dt := range value.returns.types {
					tc.push(dt.typ)
				}
			case OP_ADD, OP_SUBSTRACT:
				// TODO: Current supporting any as first argument, this might have to
				// change for type safety. But it allows to use parapoly.
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(DATA_ANY, DATA_INT), code, loc)
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
			case OP_EQUAL, OP_NOT_EQUAL, OP_GREATER, OP_GREATER_EQUAL, OP_LESS, OP_LESS_EQUAL:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(DATA_ANY, DATA_ANY), code, loc)
				tc.push(DATA_BOOL)
			case OP_FUNCTION_CALL:
				var have []DataType
				var want []DataType
				var funcRef Function
				var fns []Function

				calls := code.value.([]FunctionCall)

				for _, c := range calls {
					fns = append(fns, findFunctionByIP(c.ip))
				}

				if len(fns) == 1 {
					// We have found only one function with this signature.
					funcRef = fns[0]
				} else {
					// The function call is polymorphistic, we need to find the
					// one with the same signature and calling convention.
					for _, f := range fns {
						// To easily match the stack behavior, we first reverse it
						// (simulating we pop from it) and then shrink it to the number
						// of values expected in arguments (since stack simulation in
						// typechecking is not a dynamic array).
						var argTypes []DataType
						reverseStackOrder := tc.stackCount - len(f.arguments.types)
					    stackReversed := tc.stack[reverseStackOrder:]
						stackReducedToArgsLen := stackReversed[:len(f.arguments.types)]

						for _, d := range f.arguments.types {
							argTypes = append(argTypes, d.typ)
						}

						if reflect.DeepEqual(argTypes, stackReducedToArgsLen) {
							funcRef = f
							break
						}
					}
				}

				// We redefine the chunk value to match the function accordingly.
				// We do this while typechecking, so we can allow for polymorphism in
				// the parameters of the functions. Once we get here, we have found the
				// exact function according to the stack values provided.
				TheProgram.chunks[ifunction].code[icode].value =
					FunctionCall{name: funcRef.name, ip: funcRef.ip}

				// Doing parapoly initial checks. We go over the parameters, if parapoly
				// is enabled in this function, and then map each type of parameter that
				// expects inferred data. Once the correct types are mapped, we allow the
				// user to return a different order of definition from the original call,
				// and we make sure we maintain the type safety.
				var inferredTypes map[string]DataType
				inferredTypes = make(map[string]DataType)

				if funcRef.arguments.parapoly {
					reverseStackOrder := tc.stackCount - len(funcRef.arguments.types)
					stackReversed := tc.stack[reverseStackOrder:]

					for i, d := range funcRef.arguments.types {
						if d.typ == DATA_INFER {
							if inferredTypes[d.name] == DATA_NONE {
								inferredTypes[d.name] = stackReversed[i]
							}
						}
					}
				}

				for _, d := range funcRef.arguments.types {
					t := tc.pop()
					have = append([]DataType{t}, have...)
					want = append(want, d.typ)
				}

				assertArgumentType(have, want, code, loc)

				for _, d := range funcRef.returns.types {
					if d.typ == DATA_INFER {
						tc.push(inferredTypes[d.name])
					} else {
						tc.push(d.typ)
					}
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

	for len(dce.funcsCalled) > 0 {
		ip := dce.pop()

		for i, _ := range TheProgram.chunks {
			function := &TheProgram.chunks[i]

			if function.ip == ip {
				function.called = true

				for _, c := range function.code {
					if c.op == OP_FUNCTION_CALL {
						newCall := c.value.(FunctionCall)
						f := findFunctionByIP(newCall.ip)

						if !f.called {
							dce.push(newCall.ip)
						}
					}
				}
			}
		}
	}
}
