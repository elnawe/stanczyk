#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "chunk.h"
#include "common.h"
#include "compiler.h"
#include "debug.h"
#include "object.h"
#include "memory.h"
#include "value.h"
#include "natives.h"
#include "vm.h"

VM_t VM;

static void reset_stack() {
    VM.stack_top = VM.stack;
    VM.frame_count = 0;
}

// TODO: There's a bug in this function that it's not showing the second parameter.
static void runtime_error(const char *format, ...) {
    va_list args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputs("\n", stderr);

    // Printing the stack trace on error
    for (int i = VM.frame_count - 1; i >= 0; i--) {
        callframe_t *frame = &VM.frames[i];
        procedure_t *procedure = frame->procedure;
        size_t instruction = frame->ip - procedure->chunk.code - 1;
        fprintf(stderr, COLOR_RED"[line %d] in ", procedure->chunk.lines[instruction]);

        if (procedure->name == NULL)
            fprintf(stderr, "program\n");
        else
            fprintf(stderr, "%s()\n", procedure->name->chars);
    }

    reset_stack();
}

static void define_native(const char *name, native_proc_t procedure, int num_args) {
    push(OBJ_VAL(copy_string(name, (int)strlen(name))));
    push(OBJ_VAL(new_native(procedure, num_args)));
    table_set(&VM.symbols, AS_STRING(VM.stack[0]), VM.stack[1]);
    pop();
    pop();
}

static value_t peek(int distance) {
    return VM.stack_top[-1 - distance];
}

static bool call(procedure_t *procedure, int arg_count) {
    if (arg_count != procedure->arity) {
        runtime_error("expected %d arguments but got %d.", procedure->arity, arg_count);
        return false;
    }

    if (VM.frame_count == FRAMES_MAX) {
        runtime_error("Stack overflow.");
        return false;
    }

    callframe_t *frame = &VM.frames[VM.frame_count++];
    frame->procedure = procedure;
    frame->ip = procedure->chunk.code;
    frame->slots = VM.stack_top - arg_count - 1;
    return true;
}

static bool call_native(native_t *native, int arg_count) {
    if (arg_count != native->arity) {
        runtime_error("expected %d arguments, got $d.", native->arity, arg_count);
        return false;
    }
    value_t result = native->call(arg_count, VM.stack_top - arg_count);
    VM.stack_top -= arg_count + 1;
    push(result);
    return true;
}

static bool call_value(value_t callee, int arg_count) {
    if (IS_OBJ(callee)) {
        switch (OBJ_TYPE(callee)) {
            case OBJ_PROCEDURE:
                return call(AS_PROCEDURE(callee), arg_count);
            case OBJ_NATIVE: {
                return call_native(AS_NATIVE(callee), arg_count);
            }
            default: break;
        }
    }

    runtime_error("can only call procedures.");
    return false;
}

static bool is_falsey(value_t value) {
    return IS_NIL(value) || (IS_BOOL(value) && !AS_BOOL(value));
}

static void concatenate() {
    string_t *b = AS_STRING(pop());
    string_t *a = AS_STRING(pop());
    int length = a->length + b->length;
    char *chars = ALLOCATE(char, length + 1);
    memcpy(chars, a->chars, a->length);
    memcpy(chars + a->length, b->chars, b->length);
    chars[length] = '\0';
    string_t *result = take_string(chars, length);
    push(OBJ_VAL(result));
}

void init_VM() {
    reset_stack();
    VM.objects = NULL;
    init_table(&VM.symbols);
    init_table(&VM.strings);

    register_natives((define_native_func)define_native);
}

void free_VM() {
    free_table(&VM.strings);
    free_objects();
}

static interpret_result_t run() {
    callframe_t *frame = &VM.frames[VM.frame_count - 1];

#define READ_BYTE() (*frame->ip++)
#define READ_SHORT() (frame->ip += 2, (uint16_t)((frame->ip[-2] << 8) | frame->ip[-1]))
#define READ_CONSTANT() (frame->procedure->chunk.constants.values[READ_BYTE()])
#define READ_STRING()   AS_STRING(READ_CONSTANT())
    // TODO: The below is not the best approach I can have but  I need something
    // quick that works... Evaluating to double here will let me do both operations
    // with the caveat that I lose a few bits of ints possible and I will overflow earlier.
#define BINARY_OP(expect_type, op)                              \
    do {                                                        \
        if (!IS_NUMBER(peek(0)) || !IS_NUMBER(peek(1))) {       \
            runtime_error("operands must be numbers.");         \
            return INTERPRET_RUNTIME_ERROR;                     \
        }                                                       \
        value_type_t transform = expect_type;                   \
        transform = (IS_FLOAT(peek(0)) || IS_FLOAT(peek(1)))    \
            ? VAL_FLOAT : VAL_INT;                              \
        double b = IS_FLOAT(peek(0)) ?                          \
            AS_FLOAT(pop()) : (double)AS_INT(pop());            \
        double a = IS_FLOAT(peek(0)) ?                          \
            AS_FLOAT(pop()) : (double)AS_INT(pop());            \
        value_t result = (transform == VAL_FLOAT) ?             \
            FLOAT_VAL(a op b) : INT_VAL((long)a op (long)b);    \
        push(result);                                           \
    } while (false)
#define BINARY_OP_BOOL(op)                                  \
    do {                                                    \
        if (!IS_NUMBER(peek(0)) || !IS_NUMBER(peek(1))) {   \
            runtime_error("operands must be numbers.");     \
            return INTERPRET_RUNTIME_ERROR;                 \
        }                                                   \
        double b = IS_FLOAT(peek(0)) ?                      \
            AS_FLOAT(pop()) : (double)AS_INT(pop());        \
        double a = IS_FLOAT(peek(0)) ?                      \
            AS_FLOAT(pop()) : (double)AS_INT(pop());        \
        push(BOOL_VAL(a op b));                             \
    } while (false)

    for (;;) {
#ifdef DEBUG_TRACE_EXECUTION
        printf("          ");
        for (value_t *slot = VM.stack; slot < VM.stack_top; slot++) {
            printf("[ ");
            print_value(*slot);
            printf(" ]");
        }
        printf("\n");
        disassemble_instruction(&frame->procedure->chunk,
                                (int)(frame->ip - frame->procedure->chunk.code));
#endif

        uint8_t instruction;
        switch (instruction = READ_BYTE()) {
            case OP_CONSTANT: {
                value_t constant = READ_CONSTANT();
                push(constant);
            } break;
            case OP_NIL:      push(NIL_VAL); break;
            case OP_TRUE:     push(BOOL_VAL(true)); break;
            case OP_FALSE:    push(BOOL_VAL(false)); break;
            case OP_GET_LOCAL: {
                uint8_t slot = READ_BYTE();
                push(frame->slots[slot]);
                break;
            } break;
            case OP_SET_LOCAL: {
                uint8_t slot = READ_BYTE();
                frame->slots[slot] = peek(0);
            } break;
            case OP_GET_GLOBAL: {
                string_t *name = READ_STRING();
                value_t value;
                if (!table_get(&VM.symbols, name, &value)) {
                    runtime_error("undefined variable '%s'.", name->chars);
                    return INTERPRET_RUNTIME_ERROR;
                }
                push(value);
            } break;
            case OP_DEFINE_GLOBAL: {
                string_t *name = READ_STRING();
                table_set(&VM.symbols, name, peek(0));
                pop();
                break;
            } break;
            case OP_SET_GLOBAL: {
                string_t *name = READ_STRING();
                if (table_set(&VM.symbols, name, peek(0))) {
                    table_delete(&VM.symbols, name);
                    runtime_error("undefined variable '%s'.", name->chars);
                    return INTERPRET_RUNTIME_ERROR;
                }
                pop();
            } break;
            case OP_EQUAL: {
                value_t b = pop();
                value_t a = pop();
                push(BOOL_VAL(values_equal(a, b)));
            } break;
            case OP_GREATER: {
                if (IS_NUMBER(peek(0)) && IS_NUMBER(peek(1))) {
                    BINARY_OP_BOOL(>);
                } else {
                    runtime_error("operands are not the same type.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_LESS: {
                if (IS_NUMBER(peek(0)) && IS_NUMBER(peek(1))) {
                    BINARY_OP_BOOL(<);
                } else {
                    runtime_error("operands are not the same type.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_AND: {
                if (IS_BOOL(peek(0)) && IS_BOOL(peek(1))) {
                    bool b = AS_BOOL(pop());
                    bool a = AS_BOOL(pop());
                    push(BOOL_VAL(a && b));
                } else {
                    runtime_error("operands must be booleans.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_OR: {
                if (IS_BOOL(peek(0)) && IS_BOOL(peek(1))) {
                    bool b = AS_BOOL(pop());
                    bool a = AS_BOOL(pop());
                    push(BOOL_VAL(a || b));
                } else {
                    runtime_error("operands must be booleans.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_ADD: {
                if (IS_STRING(peek(0)) && IS_STRING(peek(1))) {
                    concatenate();
                } else if (IS_NUMBER(peek(0)) && IS_NUMBER(peek(1))) {
                    BINARY_OP(VAL_INT, +);
                } else {
                    runtime_error("operands must be int, float or string.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_SUBTRACT: {
                if (IS_NUMBER(peek(0)) && IS_NUMBER(peek(1))) {
                    BINARY_OP(VAL_INT, -);
                } else {
                    runtime_error("operands must be int or float.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_MULTIPLY: {
                if (IS_NUMBER(peek(0)) && IS_NUMBER(peek(1))) {
                    BINARY_OP(VAL_INT, *);
                } else {
                    runtime_error("operands must be int or float.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_DIVIDE: {
                if (IS_NUMBER(peek(0)) && IS_NUMBER(peek(1))) {
                    BINARY_OP(VAL_INT, /);
                } else {
                    runtime_error("operands must be int or float.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_NEGATE: {
                if (IS_NUMBER(peek(0))) {
                    if (IS_INT(peek(0))) {
                        push(INT_VAL(-AS_INT(pop())));
                    } else {
                        push(FLOAT_VAL(-AS_FLOAT(pop())));
                    }
                } else if (IS_BOOL(peek(0)) || IS_NIL(peek(0))) {
                    push(BOOL_VAL(is_falsey(pop()))); break;
                } else {
                    runtime_error("operand must be a number or a boolean.");
                    return INTERPRET_RUNTIME_ERROR;
                }
            } break;
            case OP_PRINT: {
                print_value(pop());
                printf("\n");
            } break;
            case OP_DROP: pop(); break;
            case OP_DUP: push(peek(0)); break;
            case OP_JUMP_IF_FALSE: {
                uint16_t offset = READ_SHORT();
                if (is_falsey(peek(0))) frame->ip += offset;
            } break;
            case OP_JUMP: {
                uint16_t offset = READ_SHORT();
                frame->ip += offset;
            } break;
            case OP_QUIT: {
                if (!IS_BOOL(peek(0))) {
                    runtime_error("'quit' needs a boolean on the stack");
                    return INTERPRET_RUNTIME_ERROR;
                }
                uint16_t offset = READ_SHORT();
                if (!is_falsey(peek(0))) frame->ip += offset;
            } break;
            case OP_LOOP: {
                uint16_t offset = READ_SHORT();
                frame->ip -= offset;
            } break;
            case OP_CALL: {
                int arg_count = READ_BYTE();
                if (!call_value(peek(arg_count), arg_count))
                    return INTERPRET_RUNTIME_ERROR;
                frame = &VM.frames[VM.frame_count - 1];
            } break;
            case OP_RETURN: {
                value_t result = pop();
                VM.frame_count--;
                if (VM.frame_count == 0) {
                    pop();
                    return INTERPRET_OK;
                }

                VM.stack_top = frame->slots;
                push(result);
                frame = &VM.frames[VM.frame_count - 1];
            } break;
        }
    }

#undef READ_BYTE
#undef READ_SHORT
#undef READ_CONSTANT
#undef READ_STRING
#undef BINARY_OP
#undef BINARY_OP_BOOL
}

void push(value_t value) {
    *VM.stack_top = value;
    VM.stack_top++;
}

value_t pop() {
    VM.stack_top--;
    return *VM.stack_top;
}

interpret_result_t interpret(const char *source) {
    procedure_t *procedure = compile(source);
    if (procedure == NULL) return INTERPRET_COMPILE_ERROR;

    push(OBJ_VAL(procedure));
    call(procedure, 0);
    // TODO: Main procedure can be handled here.
    return run();
}
