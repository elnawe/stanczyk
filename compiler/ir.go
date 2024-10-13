package skc

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

type Argument struct {
	kind ValueKind
	word string
}

type Arity struct {
	parapoly     bool
	types        []Argument
}

type Constant struct {
	kind  ValueKind
	token Token
	value any
	word  string
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


type Scope struct {
	ipStart    int
	ipThen     int
	tokenStart Token
	kind       ScopeName
}

type Variable struct {
	kind   ValueKind
	offset int
	scope  ScopeName
	word   string
}

type ASMValue struct {
	argumentCount int
	returnCount   int
	body          []string
}

type Assembly struct {
	arguments Arity
	results   Arity
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

type ProgramError struct {
	code  ErrorCode
	err   string
	token Token
}
