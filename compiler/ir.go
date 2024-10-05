package skc

type OpCode string

const (
	// Constants
	OP_PUSH_BOOL OpCode = "OP_PUSH_BOOL"
	OP_PUSH_BIND        =  "OP_PUSH_BIND"
	OP_PUSH_CHAR	    =  "OP_PUSH_CHAR"
	OP_PUSH_INT		    =  "OP_PUSH_INT"
	OP_PUSH_PTR		    =  "OP_PUSH_PTR"
	OP_PUSH_STR		    =  "OP_PUSH_STR"

	// FLOW CONTROL
	OP_IF_START         =  "OP_IF_START"
	OP_IF_ELSE          =  "OP_IF_ELSE"
	OP_IF_END           =  "OP_IF_END"
	OP_LOOP_END		    =  "OP_LOOP_END"
	OP_LOOP_SETUP	    =  "OP_LOOP_SETUP"
	OP_LOOP_START	    =  "OP_LOOP_START"

	OP_LET_BIND		    =  "OP_LET_BIND"
	OP_LET_UNBIND	    =  "OP_LET_UNBIND"
	OP_REBIND		    =  "OP_REBIND"

	OP_ADD			    =  "OP_ADD"
	OP_ARGC			    =  "OP_ARGC"
	OP_ARGV			    =  "OP_ARGV"
	OP_ASSEMBLY		    =  "OP_ASSEMBLY"
	OP_CAST			    =  "OP_CAST"
	OP_DIVIDE		    =  "OP_DIVIDE"
	OP_END_IF		    =  "OP_END_IF"
	OP_END_LOOP		    =  "OP_END_LOOP"
	OP_EQUAL		    =  "OP_EQUAL"
	OP_FUNCTION_CALL    =  "OP_FUNCTION_CALL"
	OP_GREATER		    =  "OP_GREATER"
	OP_GREATER_EQUAL    =  "OP_GREATER_EQUAL"
	OP_JUMP			    =  "OP_JUMP"
	OP_JUMP_IF_FALSE    =  "OP_JUMP_IF_FALSE"
	OP_LESS			    =  "OP_LESS"
	OP_LESS_EQUAL	    =  "OP_LESS_EQUAL"
	OP_LOAD8		    =  "OP_LOAD8"
	OP_LOAD16		    =  "OP_LOAD16"
	OP_LOAD32		    =  "OP_LOAD32"
	OP_LOAD64		    =  "OP_LOAD64"
	OP_LOOP			    =  "OP_LOOP"
	OP_MODULO		    =  "OP_MODULO"
	OP_MULTIPLY		    =  "OP_MULTIPLY"
	OP_NOT_EQUAL	    =  "OP_NOT_EQUAL"
	OP_RET			    =  "OP_RET"
	OP_SUBSTRACT	    =  "OP_SUBSTRACT"
	OP_STORE8		    =  "OP_STORE8"
	OP_STORE16		    =  "OP_STORE16"
	OP_STORE32		    =  "OP_STORE32"
	OP_STORE64		    =  "OP_STORE64"

	OP_EOC			    =  "OP_EOC"
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

type Bind struct {
	id       int
	name     string
	writable bool
}

type Binding struct {
	count []int
	words []string
}

type ScopeCondition string
type ScopeType int

const (
	LC_NONE ScopeCondition	= ""
	LC_LESS					= "jl"
	LC_LESS_EQUAL			= "jle"
	LC_GREATER				= "jg"
	LC_GREATER_EQUAL		= "jge"
	LC_EQUAL				= "je"
	LC_NOT_EQUAL			= "jne"
)

const (
	SCOPE_BIND ScopeType = iota
	SCOPE_LOOP
	SCOPE_IF
	SCOPE_ELSE
)

type Scope struct {
	condition  ScopeCondition
	ipStart    int
	ipThen     int
	tokenStart Token
	typ        ScopeType
}

type Function struct {
	ip          int
	name        string
	loc         Location

	arguments   Arity
	returns     Arity
	bindings    Binding
	code        []Code
	scope       []Scope

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
