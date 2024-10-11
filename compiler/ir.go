package skc

type Address string

const (
	BINDING Address = "BINDING"
	GLOBAL_VARIABLE = "GLOBAL"
	LOCAL_VARIABLE  = "LOCAL"
)

type OpCode string

const (
	// Constants
	OP_PUSH_BOOL OpCode		=  "OP_PUSH_BOOL"
	OP_PUSH_BIND			=  "OP_PUSH_BIND"
	OP_PUSH_BIND_ADDR		=  "OP_PUSH_BIND_ADDR"
	OP_PUSH_CHAR			=  "OP_PUSH_CHAR"
	OP_PUSH_INT				=  "OP_PUSH_INT"
	OP_PUSH_STR				=  "OP_PUSH_STR"
	OP_PUSH_VAR_GLOBAL		=  "OP_PUSH_VAR_GLOBAL"
	OP_PUSH_VAR_GLOBAL_ADDR	=  "OP_PUSH_VAR_GLOBAL_ADDR"
	OP_PUSH_VAR_LOCAL		=  "OP_PUSH_VAR_LOCAL"
	OP_PUSH_VAR_LOCAL_ADDR	=  "OP_PUSH_VAR_LOCAL_ADDR"

	OP_LOAD_BYTE	= "OP_LOAD_BYTE"
	OP_STORE_BYTE	= "OP_STORE_BYTE"
	OP_PUSH_LET		= "OP_PUSH_LET"

	OP_PUSH_GLOBAL_VARIABLE =  "OP_PUSH_GLOBAL_VARIABLE"
	OP_PUSH_LOCAL_VARIABLE  =  "OP_PUSH_LOCAL_VARIABLE"
	OP_PUSH_VALUE           =  "OP_PUSH_VALUE"

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

	OP_LOAD					=  "OP_LOAD"
	OP_STORE				=  "OP_STORE"
	OP_LOAD_CHAR			=  "OP_LOAD_CHAR"
	OP_STORE_CHAR			=  "OP_STORE_CHAR"

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

type ValueKind string

const (
	UNKNOWN ValueKind = "unknown"
	ANY               = "any"
	BOOLEAN           = "bool"
	BYTE              = "byte"
	INT64             = "int"
	RAWPOINTER        = "ptr"
	STRING            = "str"
	VARIADIC          = "$T"
)

type Value struct {
	kind ValueKind
	token Token
	variant any
}

type ValueBoolean int

type ValueByte    uint8

type ValueInt64   int

type ValuePointer struct {
	address Address
	kind    ValueKind
	offset  int
}

type ValueString  string

type DataType int

const (
	DATA_NONE DataType	= iota
	DATA_ANY
	DATA_BOOL
	DATA_CHAR
	DATA_INFER
	DATA_INT
	DATA_INT_PTR
	DATA_PTR
	DATA_STR
)

type CompilerError struct {
	code    ErrorCode
	message string
	token   Token
}

type Program struct {
	errors           []CompilerError

	chunks           []Function
	constants        []Constant
	variables        []Variable
	staticMemorySize int
}

type Argument struct {
	name  string
	typ   DataType
	kind  ValueKind
}

type Arity struct {
	variadic     bool
	types        []Argument
}

type Constant struct {
	value Value
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
	kind       ScopeKind
}

type Variable struct {
	address Address
	kind    ValueKind
	typ     DataType
	offset  int
	word    string
}

type Function struct {
	ip   int
	loc  Location
	name string
	word string

	arguments       Arity
	returns         Arity
	bindings        Binding
	code            []Code
	scope           []Scope
	constants       []Constant
	variables       []Variable
	localMemorySize int

	called   bool
	error    bool
	internal bool
	parsed   bool
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

func (this *Function) WriteCode(code Code) {
	this.code = append(this.code, code)
}
