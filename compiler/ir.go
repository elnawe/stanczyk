package skc

import (
	"fmt"
)

type OpCode string

const (
	// Constants
	OP_PUSH_BOOL OpCode = "OP_PUSH_BOOL"
	OP_PUSH_BYTE        = "push byte"
	OP_PUSH_BIND        = "OP_PUSH_BIND"
 	OP_PUSH_BIND_ADDR		= "OP_PUSH_BIND_ADDR"
	OP_PUSH_INT				= "OP_PUSH_INT"
	OP_PUSH_STR				= "OP_PUSH_STR"
	OP_PUSH_VAR_GLOBAL		= "OP_PUSH_VAR_GLOBAL"
	OP_PUSH_VAR_GLOBAL_ADDR	= "OP_PUSH_VAR_GLOBAL_ADDR"
	OP_PUSH_VAR_LOCAL		= "OP_PUSH_VAR_LOCAL"
	OP_PUSH_VAR_LOCAL_ADDR	= "OP_PUSH_VAR_LOCAL_ADDR"

	// FLOW CONTROL
	OP_IF_START				=  "OP_IF_START"
	OP_IF_ELSE				=  "OP_IF_ELSE"
	OP_IF_END				=  "OP_IF_END"
	OP_LOOP_END				=  "OP_LOOP_END"
	OP_LOOP_SETUP			=  "OP_LOOP_SETUP"
	OP_LOOP_START			=  "OP_LOOP_START"

	OP_LET_BIND				=  "OP_LET_BIND"
	OP_LET_UNBIND			=  "OP_LET_UNBIND"
	OP_REBIND				=  "OP_REBIND"

	// POINTER INTRINSICS
	OP_LOAD       = "@"
	OP_LOAD_BYTE  = "@b"
	OP_STORE      = "!"
	OP_STORE_BYTE = "!b"

	// ARITHMETICS
	OP_ADD					=  "OP_ADD"
	OP_DIVIDE				=  "OP_DIVIDE"
	OP_MODULO				=  "OP_MODULO"
	OP_MULTIPLY				=  "OP_MULTIPLY"
	OP_SUBSTRACT			=  "OP_SUBSTRACT"

	// BOOLEAN ARITHMETICS
	OP_GREATER				=  "OP_GREATER"
	OP_GREATER_EQUAL		=  "OP_GREATER_EQUAL"
	OP_LESS					=  "OP_LESS"
	OP_LESS_EQUAL			=  "OP_LESS_EQUAL"
	OP_NOT_EQUAL			=  "OP_NOT_EQUAL"

	OP_ARGC					=  "OP_ARGC"
	OP_ARGV					=  "OP_ARGV"
	OP_ASSEMBLY				=  "OP_ASSEMBLY"
	OP_CAST					=  "OP_CAST"
	OP_EQUAL				=  "OP_EQUAL"
	OP_FUNCTION_CALL		=  "OP_FUNCTION_CALL"
	OP_RET					=  "OP_RET"

	OP_EOC					=  "OP_EOC"
)

type ValueKind int

const (
	NONE ValueKind = iota
	ANY
	BOOL
	BYTE
	INT
	RAWPOINTER
	STRING
	VARIADIC
)

type Program struct {
	chunks           []Function
	constants        []Constant
	errors           []ProgramError
	variables        []Variable
	staticMemorySize int
}

type Argument struct {
	name  string
	typ   ValueKind
}

type Arity struct {
	parapoly     bool
	types        []Argument
}

type Constant struct {
	word  string
	value int
}

type Bind struct {
	id       int
	name     string
	writable bool
}

type Binding struct {
	count []int
	words []string
}

type ScopeType int

const (
	SCOPE_BIND ScopeType = iota
	SCOPE_LOOP
	SCOPE_IF
	SCOPE_ELSE
)

type Scope struct {
	ipStart    int
	ipThen     int
	tokenStart Token
	typ        ScopeType
}

type Variable struct {
	dtype  ValueKind
	offset int
	word   string
}

type Function struct {
	ip              int
	name            string
	loc             Location

	arguments       Arity
	returns         Arity
	bindings        Binding
	code            []Code
	scope           []Scope
	constants       []Constant
	variables       []Variable

	localMemorySize int
	parsed          bool
	called          bool
	internal        bool
}

type ASMValue struct {
	argumentCount int
	returnCount   int
	body          []string
}

type Assembly struct {
	arguments Arity
	returns   Arity
	body      []string
}

type Code struct {
	loc   Location
	op    OpCode
	value any
}

type Chunk struct {
	code []Code
}

type FunctionCall struct {
	name string
	ip   int
}

type ProgramError struct {
	err string
	step CompilationStep
}

func (this *Program) error(step CompilationStep, msg ErrorMessage, args ...any) {
	pErr := ProgramError{err: fmt.Sprintf(string(msg), args...), step: step}
	this.errors = append(this.errors, pErr)
}

func (this *Function) WriteCode(code Code) {
	this.code = append(this.code, code)
}
