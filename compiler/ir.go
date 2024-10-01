package skc

type OpCode int

const (
	// Constants
	OP_PUSH_BOOL OpCode = iota
	OP_PUSH_BOUND
	OP_PUSH_CHAR
	OP_PUSH_INT
	OP_PUSH_PTR
	OP_PUSH_STR

	OP_LOOP_START
	OP_LOOP_END

	// Intrinscis
	OP_ADD
	OP_ARGC
	OP_ARGV
	OP_ASSEMBLY
	OP_BIND
	OP_CAST
	OP_DIVIDE
	OP_END_IF
	OP_END_LOOP
	OP_EQUAL
	OP_FUNCTION_CALL
	OP_GREATER
	OP_GREATER_EQUAL
	OP_JUMP
	OP_JUMP_IF_FALSE
	OP_LESS
	OP_LESS_EQUAL
	OP_LOAD8
	OP_LOAD16
	OP_LOAD32
	OP_LOAD64
	OP_LOOP
	OP_MODULO
	OP_MULTIPLY
	OP_NOT_EQUAL
	OP_RET
	OP_ROTATE
	OP_SUBSTRACT
	OP_STORE8
	OP_STORE16
	OP_STORE32
	OP_STORE64
	OP_TAKE

	// Special
	OP_EOC
)

type DataType int

const (
	DATA_NONE DataType = iota
	DATA_ANY
	DATA_BOOL
	DATA_CHAR
	DATA_INFER
	DATA_INT
	DATA_PTR
)

type ScopeStartCondition string

const (
	LC_NONE ScopeStartCondition = ""
	LC_LESS						= "jl"
	LC_LESS_EQUAL				= "jle"
	LC_GREATER					= "jg"
	LC_GREATER_EQUAL			= "jge"
	LC_EQUAL					= "je"
	LC_NOT_EQUAL				= "jne"
)

type LoopType int

type Loop struct {
	condition ScopeStartCondition
	gotoIP    int
	level     int
	typ       TokenType
}

type Bound struct {
	word string
	id   int
}

type Program struct {
	chunks    []Function
	variables []Object
}

type Argument struct {
	name  string
	typ   DataType
}

type Arity struct {
	parapoly     bool
	types        []Argument
}

type Function struct {
	ip          int
	name        string
	arguments   Arity
	returns     Arity
	loc         Location
	bindings    []Bound
	code        []Code
	parsed      bool
	called      bool
	internal    bool
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

func (this *Function) WriteCode(code Code) {
	this.code = append(this.code, code)
}
