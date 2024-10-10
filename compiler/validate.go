package skc

import (
	"fmt"
	"reflect"
)

const STACK_SIZE = 1024

type Typecheck struct {
	stack       [STACK_SIZE]ValueKind
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
		r += getValueKindName(tc.stack[index])

		if (index != tc.stackCount - 1) {
			r += " "
		}
	}

	return r
}

func getValueKindName(v ValueKind) string {
	r := ""
	switch v {
	case NONE:  r = ""
	case BOOL:  r = "bool"
	case BYTE:  r = "char"
	case INFER: r = "$type"
	case INT:	 r = "int"
	case PTR:   r = "ptr"
	case STR:   r = "str"
	case ANY:   r = "any"
	}
	return r
}

func getValueKindNames(dt []ValueKind) string {
	r := ""

	for i, v := range dt {
		r += getValueKindName(v)
		if i != len(dt) -1 && v != NONE {
			r += " "
		}
	}

	return r
}

func assertArgumentTypes(test []ValueKind, want [][]ValueKind, code Code, loc Location) {
	var errFound []bool

	for _, w := range want {
		err := false

		for i, t := range test {
			if w[i] == ANY {
				if t == NONE {
					err = true
					break
				}
			} else {
				if w[i] != t && t != ANY {
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
			wantsText += "(" + getValueKindNames(w) + ")"

			if i != len(want) - 1 {
				wantsText += " or "
			}
		}

		msg := fmt.Sprintf(MsgTypecheckArgumentsTypesMismatch,
			code.op, getValueKindNames(test), wantsText)
		ReportErrorAtLocation(msg, loc)
		ExitWithError(CodeTypecheckError)
	}
}

func assertArgumentType(test []ValueKind, want []ValueKind, code Code, loc Location) {
	errFound := false

	for i, t := range test {
		if want[i] == ANY || want[i] == INFER {
			if t == NONE {
				errFound = true
				break
			}
		} else {
			if want[i] != t && t != ANY {
				errFound = true
				break
			}
		}
	}

	if errFound {
		fmt.Println(code)
		msg := fmt.Sprintf(MsgTypecheckArgumentsTypeMismatch,
			code.op, getValueKindNames(test), getValueKindNames(want))
		ReportErrorAtLocation(msg, loc)
		ExitWithError(CodeTypecheckError)
	}
}

func dtArray(values ...ValueKind) []ValueKind {
	var r []ValueKind
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
	this.stack = [STACK_SIZE]ValueKind{}
	this.stackCount = 0
}

func (this *Typecheck) push(t ValueKind) {
	this.stack[this.stackCount] = t
	this.stackCount++
}

func (this *Typecheck) pop() ValueKind {
	if this.stackCount == 0 {
		return NONE
	}
	this.stackCount--
	v := this.stack[this.stackCount]
	this.stack[this.stackCount] = NONE
	return v
}

func ValidateRun() {
	mainHandled := false

	for ifunction, function := range TheProgram.chunks {
		var bindings []ValueKind
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
			value := code.value

			switch instruction {
			// CONSTANT
			case OP_PUSH_BOOL:
				tc.push(BOOL)
			case OP_PUSH_BIND:
				value := code.value.(int)
				tc.push(bindings[value])
			case OP_PUSH_BIND_ADDR:
				tc.push(PTR)
			case OP_PUSH_BYTE:
				tc.push(BYTE)
			case OP_PUSH_INT:
				tc.push(INT)
			case OP_PUSH_STR:
				tc.push(STR)
			case OP_PUSH_VAR_GLOBAL:
				for _, v := range TheProgram.variables {
					if v.offset == value.(int) {
						tc.push(v.dtype)
					}
				}
			case OP_PUSH_VAR_GLOBAL_ADDR:
				tc.push(PTR)
			case OP_PUSH_VAR_LOCAL:
				for _, v := range function.variables {
					if v.offset == value.(int) {
						tc.push(v.dtype)
					}
				}
			case OP_PUSH_VAR_LOCAL_ADDR:
				tc.push(PTR)

			// MATH ARITHMETICS
			case OP_MULTIPLY:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, INT), code, loc)
				tc.push(INT)

			case OP_STORE:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(ANY, PTR), code, loc)
			case OP_STORE_BYTE:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(
					dtArray(ANY, PTR),
					dtArray(a, b), code, loc,
				)
			case OP_LOAD:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(PTR), code, loc)
				tc.push(INT)
			case OP_LOAD_BYTE:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, PTR), code, loc)
				tc.push(BYTE)

			case OP_LET_BIND:
				var have []ValueKind
				var wants []ValueKind
				newBinds := code.value.(int)
				for i := newBinds; i > 0; i-- {
					a := tc.pop()
					bindings = append([]ValueKind{a}, bindings...)
					have = append([]ValueKind{a}, have...)
					wants = append(wants, ANY)
				}
				assertArgumentType(have, wants, code, loc)
			case OP_LET_UNBIND:
				unbound := code.value.(int)
				bindings = bindings[:len(bindings)-unbound]
			case OP_REBIND:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(ANY), code, loc)

			// Intrinsics
			case OP_ASSEMBLY:
				var have []ValueKind
				var want []ValueKind
				val := value.(ASMValue)

				for i := val.argumentCount; i > 0; i-- {
					a := tc.pop()
					have = append([]ValueKind{a}, have...)
					want = append(want, ANY)
				}
				for i := 0; i < val.returnCount; i++ {
					tc.push(INT)
				}
			case OP_ADD, OP_SUBSTRACT:
				// TODO: Current supporting any as first argument, this might have to
				// change for type safety. But it allows to use parapoly.
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(ANY, INT), code, loc)
				if a == INT && b == INT {
					tc.push(INT)
				} else if a == BYTE || b == BYTE {
					tc.push(BYTE)
				} else {
					tc.push(PTR)
				}
			case OP_ARGC:
				tc.push(INT)
			case OP_ARGV:
				tc.push(PTR)
			case OP_CAST:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(ANY), code, loc)
				tc.push(code.value.(ValueKind))
			case OP_DIVIDE:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, INT), code, loc)
				tc.push(INT)
			case OP_MODULO:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, INT), code, loc)
				tc.push(INT)
			case OP_EQUAL, OP_NOT_EQUAL, OP_GREATER, OP_GREATER_EQUAL, OP_LESS, OP_LESS_EQUAL:
				b := tc.pop()
				a := tc.pop()
				assertArgumentType(dtArray(a, b), dtArray(ANY, ANY), code, loc)
				tc.push(BOOL)
			case OP_FUNCTION_CALL:
				var have []ValueKind
				var want []ValueKind
				var fns []Function
				var funcRef Function

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
						var argTypes []ValueKind
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
				var inferredTypes map[string]ValueKind
				inferredTypes = make(map[string]ValueKind)

				if funcRef.arguments.parapoly {
					reverseStackOrder := tc.stackCount - len(funcRef.arguments.types)
					stackReversed := tc.stack[reverseStackOrder:]

					for i, d := range funcRef.arguments.types {
						if d.typ == INFER {
							if inferredTypes[d.name] == NONE {
								inferredTypes[d.name] = stackReversed[i]
							}
						}
					}
				}

				for _, d := range funcRef.arguments.types {
					t := tc.pop()
					have = append([]ValueKind{t}, have...)
					want = append(want, d.typ)
				}

				assertArgumentType(have, want, code, loc)

				for _, d := range funcRef.returns.types {
					if d.typ == INFER {
						tc.push(inferredTypes[d.name])
					} else {
						tc.push(d.typ)
					}
				}

			case OP_IF_START:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(BOOL), code, loc)
				tc.scope++
				snapshots[tc.scope] = tc
			case OP_IF_END, OP_IF_ELSE:

			case OP_LOOP_END:
				tc.scope--
			case OP_LOOP_SETUP:
				// NOTE: This is just meant to be a label in the code.
			case OP_LOOP_START:
				a := tc.pop()
				assertArgumentType(dtArray(a), dtArray(BOOL), code, loc)
				tc.scope++

			case OP_RET:

			default:
				fmt.Println("Unhandled", code.op)
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
