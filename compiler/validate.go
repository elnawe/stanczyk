package skc

import (
	"fmt"
	"reflect"
	"slices"
)

const STACK_SIZE = 1024

type Stack []ValueKind

type Simulation struct {
	calledIPs   []int
	currentFn   *Function
	currentCode *Code
	mainHandled bool
	stack       Stack
	scope       int
	snapshots   [10]Stack
}

func (this *Simulation) pop() ValueKind {
	if len(this.stack) == 0 {
		ReportErrorAtFunction(
			this.currentFn,
			StackUnderflow, this.currentCode.op, this.currentCode.loc.l,
		)
		ExitWithError(CriticalError)
	}

	lastIndex := len(this.stack)-1
	r := this.stack[lastIndex]
	this.stack = slices.Clone(this.stack[:lastIndex])
	return r
}

func (this *Simulation) push(v ValueKind) {
	this.stack = append(this.stack, v)
}

func (this *Simulation) popIP() int {
	if len(this.calledIPs) == 0 {
		ReportErrorAtEOF(string(CompilerBug))
		ExitWithError(CriticalError)
	}

	lastIndex := len(this.calledIPs)-1
	result := this.calledIPs[lastIndex]
	this.calledIPs = slices.Clone(this.calledIPs[:lastIndex])
	return result
}

func (this *Simulation) pushIP(ip int) {
	this.calledIPs = append(this.calledIPs, ip)
}

func (this *Simulation) reset() {
	this.currentFn    = nil
	this.currentCode  = nil
	this.scope        = 0
	this.stack        = make(Stack, 0, 0)
}

func (this *Simulation) setup(fn *Function) {
	this.currentFn = fn

	arguments := fn.arguments.types
	results := fn.results.types

	if fn.word == "main" {
		this.mainHandled = true
		this.pushIP(fn.ip)

		if len(arguments) > 0 || len(results) > 0 {
			TheProgram.error(fn.token, MainFunctionInvalidSignature, len(arguments), len(results))
		}
	}

	for _, p := range arguments {
		this.push(p.kind)
	}
}

func (this *Simulation) validate() {
	stackCount := len(this.stack)
	expectedResults := len(this.currentFn.results.types)

	if stackCount != expectedResults {
		ReportErrorAtFunction(this.currentFn,
			StackUnhandled, stackCount, expectedResults, getStackValues())
		ExitWithError(UnhandledStackError)
	}

	sim.reset()
}

var sim = &TheProgram.simulation

func getStackValues() string {
	stackCount := len(sim.stack)
	r := ""

	for index := 0; index < stackCount; index++ {
		r += valueKindString(sim.stack[index])

		if (index != stackCount - 1) {
			r += " "
		}
	}

	return r
}

func valueKindString(v ValueKind) string {
	r := ""
	switch v {
	case NONE:       r = "unknown"
	case ANY:        r = "any"
	case BOOL:       r = "bool"
	case BYTE:       r = "byte"
	case INT:        r = "int"
	case RAWPOINTER: r = "rawptr"
	case STRING:     r = "str"
	case VARIADIC:   r = "$T"
	}
	return r
}

func valueKindStrings(dt []ValueKind) string {
	r := ""

	for i, v := range dt {
		r += valueKindString(v)
		if i != len(dt) -1 && v != NONE {
			r += " "
		}
	}

	return r
}

func assertArgumentTypes(test []ValueKind, want [][]ValueKind, code *Code, loc Location) {
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
			wantsText += "(" + valueKindStrings(w) + ")"

			if i != len(want) - 1 {
				wantsText += " or "
			}
		}

		msg := fmt.Sprintf(MsgTypecheckArgumentsTypesMismatch,
			code.op, valueKindStrings(test), wantsText)
		ReportErrorAtLocation(msg, loc)
		ExitWithError(CodeTypecheckError)
	}
}

func assertArgumentType(test []ValueKind, want []ValueKind, code *Code, loc Location) {
	errFound := false

	for i, t := range test {
		if want[i] == ANY || want[i] == VARIADIC {
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
			code.op, valueKindStrings(test), valueKindStrings(want))
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

func ValidateRun() {
	for indexFn, _ := range TheProgram.chunks {
		var bindings []ValueKind
		function := &TheProgram.chunks[indexFn]
		sim.setup(function)

		for indexCode, _ := range function.code {
			code := &function.code[indexCode]
			sim.currentCode = code
			instruction := code.op
			loc := code.loc
			value := code.value

			switch instruction {
			// CONSTANT
			case OP_PUSH_BOOL:
				sim.push(BOOL)
			case OP_PUSH_BIND:
				value := code.value.(int)
				sim.push(bindings[value])
			case OP_PUSH_BIND_ADDR:
				sim.push(RAWPOINTER)
			case OP_PUSH_BYTE:
				sim.push(BYTE)
			case OP_PUSH_INT:
				sim.push(INT)
			case OP_PUSH_STR:
				sim.push(STRING)
			case OP_PUSH_VAR_GLOBAL:
				for _, v := range TheProgram.variables {
					if v.offset == value.(int) {
						sim.push(v.kind)
					}
				}
			case OP_PUSH_VAR_GLOBAL_ADDR:
				sim.push(RAWPOINTER)
			case OP_PUSH_VAR_LOCAL:
				for _, v := range function.variables {
					if v.offset == value.(int) {
						sim.push(v.kind)
					}
				}
			case OP_PUSH_VAR_LOCAL_ADDR:
				sim.push(RAWPOINTER)

			// MATH ARITHMETICS
			case OP_MULTIPLY:
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, INT), code, loc)
				sim.push(INT)

			case OP_STORE:
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(dtArray(a, b), dtArray(ANY, RAWPOINTER), code, loc)
			case OP_STORE_BYTE:
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(
					dtArray(ANY, RAWPOINTER),
					dtArray(a, b), code, loc,
				)
			case OP_LOAD:
				a := sim.pop()
				assertArgumentType(dtArray(a), dtArray(RAWPOINTER), code, loc)
				sim.push(INT)
			case OP_LOAD_BYTE:
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, RAWPOINTER), code, loc)
				sim.push(BYTE)

			case OP_LET_BIND:
				var have []ValueKind
				var wants []ValueKind
				newBinds := code.value.(int)
				for i := newBinds; i > 0; i-- {
					a := sim.pop()
					bindings = append([]ValueKind{a}, bindings...)
					have = append([]ValueKind{a}, have...)
					wants = append(wants, ANY)
				}
				assertArgumentType(have, wants, code, loc)
			case OP_LET_UNBIND:
				unbound := code.value.(int)
				bindings = bindings[:len(bindings)-unbound]
			case OP_REBIND:
				a := sim.pop()
				assertArgumentType(dtArray(a), dtArray(ANY), code, loc)

			// Intrinsics
			case OP_ASSEMBLY:
				var have []ValueKind
				var want []ValueKind
				val := value.(ASMValue)

				for i := val.argumentCount; i > 0; i-- {
					a := sim.pop()
					have = append([]ValueKind{a}, have...)
					want = append(want, ANY)
				}
				for i := 0; i < val.returnCount; i++ {
					sim.push(INT)
				}
			case OP_ADD, OP_SUBSTRACT:
				// TODO: Current supporting any as first argument, this might have to
				// change for type safety. But it allows to use parapoly.
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(dtArray(a, b), dtArray(ANY, INT), code, loc)
				if a == INT && b == INT {
					sim.push(INT)
				} else if a == BYTE || b == BYTE {
					sim.push(BYTE)
				} else {
					sim.push(RAWPOINTER)
				}
			case OP_ARGC:
				sim.push(INT)
			case OP_ARGV:
				sim.push(RAWPOINTER)
			case OP_CAST:
				a := sim.pop()
				assertArgumentType(dtArray(a), dtArray(ANY), code, loc)
				sim.push(code.value.(ValueKind))
			case OP_DIVIDE:
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, INT), code, loc)
				sim.push(INT)
			case OP_MODULO:
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(dtArray(a, b), dtArray(INT, INT), code, loc)
				sim.push(INT)
			case OP_EQUAL, OP_NOT_EQUAL, OP_GREATER, OP_GREATER_EQUAL, OP_LESS, OP_LESS_EQUAL:
				b := sim.pop()
				a := sim.pop()
				assertArgumentType(dtArray(a, b), dtArray(ANY, ANY), code, loc)
				sim.push(BOOL)
			case OP_FUNCTION_CALL:
				var have []ValueKind
				var want []ValueKind
				var fns []Function
				var funcRef *Function

				calls := code.value.([]int)

				for _, ip := range calls {
					fns = append(fns, findFunctionByIP(ip))
				}

				if len(fns) == 1 {
					// We have found only one function with this signature.
					funcRef = &fns[0]
				} else {
					// The function call is polymorphistic, we need to find the
					// one with the same signature and calling convention.
					for _, f := range fns {
						// To easily match the stack behavior, we first reverse it
						// (simulating we pop from it) and then shrink it to the number
						// of values expected in arguments (since stack sim in
						// typechecking is not a dynamic array).
						var match Stack
						reversed := slices.Clone(sim.stack)
						slices.Reverse(reversed)
						stackReducedToArgsLen := reversed[:len(f.arguments.types)]

						for _, t := range f.arguments.types {
							match = append(match, t.kind)
						}

						if reflect.DeepEqual(match, stackReducedToArgsLen) {
							funcRef = &f
							break
						}
					}
				}

				// We redefine the chunk value to match the function accordingly.
				// We do this while typechecking, so we can allow for polymorphism in
				// the parameters of the functions. Once we get here, we have found the
				// exact function according to the stack values provided.
				code.value = funcRef.ip

				// Doing parapoly initial checks. We go over the parameters, if parapoly
				// is enabled in this function, and then map each type of parameter that
				// expects inferred data. Once the correct types are mapped, we allow the
				// user to return a different order of definition from the original call,
				// and we make sure we maintain the type safety.
				var inferredTypes map[string]ValueKind
				inferredTypes = make(map[string]ValueKind)

				if funcRef.arguments.parapoly {
					sizeToArgs := len(sim.stack) - len(funcRef.arguments.types)
					reducedStack := slices.Clone(sim.stack[sizeToArgs:])

					for i, d := range funcRef.arguments.types {
						if d.kind == VARIADIC {
							if inferredTypes[d.word] == NONE {
								inferredTypes[d.word] = reducedStack[i]
							}
						}
					}
				}

				for _, d := range funcRef.arguments.types {
					t := sim.pop()
					have = append([]ValueKind{t}, have...)
					want = append(want, d.kind)
				}

				assertArgumentType(have, want, code, loc)

				for _, d := range funcRef.results.types {
					if d.kind == VARIADIC {
						sim.push(inferredTypes[d.word])
					} else {
						sim.push(d.kind)
					}
				}

			case OP_IF_START:
				a := sim.pop()
				assertArgumentType(dtArray(a), dtArray(BOOL), code, loc)
				sim.scope++
				sim.snapshots[sim.scope] = sim.stack
			case OP_IF_END, OP_IF_ELSE:

			case OP_LOOP_END:
				sim.scope--
			case OP_LOOP_SETUP:
				// NOTE: This is just meant to be a label in the code.
			case OP_LOOP_START:
				a := sim.pop()
				assertArgumentType(dtArray(a), dtArray(BOOL), code, loc)
				sim.scope++

			case OP_RET:

			default:
				fmt.Println("Unhandled", code.op)
			}
		}

		sim.validate()
	}

	if !sim.mainHandled {
		ReportErrorAtEOF(string(MainFunctionUndefined))
		ExitWithError(CriticalError)
	}

	for len(sim.calledIPs) > 0 {
		ip := sim.popIP()

		for i, _ := range TheProgram.chunks {
			function := &TheProgram.chunks[i]

			if function.ip == ip {
				function.called = true

				for _, c := range function.code {
					if c.op == OP_FUNCTION_CALL {
						ip := c.value.(int)
						f := findFunctionByIP(ip)

						if !f.called {
							sim.pushIP(ip)
						}
					}
				}
			}
		}
	}
}
