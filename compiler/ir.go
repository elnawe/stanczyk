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

	// Intrinscis
	OP_ADD
	OP_ARGC
	OP_ARGV
	OP_BIND
	OP_CAST
	OP_DIVIDE
	OP_DROP
	OP_DUP
	OP_END_IF
	OP_END_LOOP
	OP_EQUAL
	OP_EXTERN
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
	OP_MULTIPLY
	OP_NOT_EQUAL
	OP_OVER
	OP_RET
	OP_ROTATE
	OP_SUBSTRACT
	OP_STORE8
	OP_STORE16
	OP_STORE32
	OP_STORE64
	OP_SWAP
	OP_TAKE

	// Special
	OP_WORD
	OP_EOC
)

type DataType int

const (
	DATA_EMPTY DataType = iota
	DATA_BOOL
	DATA_CHAR
	DATA_INT
	DATA_PTR
	DATA_ANY
)

type Bound struct {
	word string
	id   int
}

type Program struct {
	chunks   []Function
	memories []Object
}

type Function struct {
	ip          int
	name        string
	loc         Location
	args        []DataType
	rets        []DataType
	code        []Code
	polymorphic bool
	called      bool
	internal    bool
}

type Extern struct {
	args []DataType
	body []string
	rets []DataType
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
