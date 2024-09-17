package main

import "core:fmt"
import "core:slice"
import "core:strconv"
import "core:strings"

StackValue :: struct {
    identifier: string,
    type: DataType,
}

Function_Declaration :: struct {
    arguments: [dynamic]DataType,
    body: [dynamic]StatementOrExpression,
    returns: [dynamic]DataType,
    identifier: string,
    name: string,
    start: Location,
    end: Location,
    start_index: int,
    end_index: int,
}

StatementOrExpression :: union {
    BinaryArithmeticExpression,
    FunctionCall,
    Literal,
    NativeCall,
    ReturnExpression,
}

BinaryArithmeticExpression :: struct {
    identifier: string,
    left_type: DataType,
    right_type: DataType,
    operation: string,
}

FunctionCall :: struct {
    identifier: string,
    argument_ids: [dynamic]string,
    callee: string,
    return_ids: [dynamic]string,
}

Literal :: struct {
    identifier: string,
    type: DataType,
    value: Value,
}

NativeCall :: struct {
    argument_ids: [dynamic]string,
    callee: NativeFunctionId,
}

ReturnExpression :: struct {
    identifiers: [dynamic]string,
}

// Gets the current index for the program token where the function identifier is,
// then returns the new index, after the function statement is closed.
register_function :: proc(index: int) -> int {
    fn: Function_Declaration
    new_index := index + 1
    fn_id_token := program.tokens[new_index]

    // Go through the function declaration, figure out if the declaration structure
    // is correct, if it has arguments and returns
    function_valid := true
    function_has_arguments := false
    function_has_returns := false
    function_arguments_count := 0
    function_returns_count := 0
    skip_body := false

    for lookup_index := new_index; lookup_index < len(program.tokens); lookup_index += 1 {
        token := program.tokens[lookup_index]

        if token.type == .EOF {
            function_valid = false
            error_at_ast(token, "AST__FUNCTION__MISSING_CLOSING_STATEMENT")
            panic_execution(.AST)
        }

        if skip_body {
            if token.type == .PAREN_RIGHT {
                fn.end = token.location
                fn.end_index = lookup_index
                break
            }
        } else {
            #partial switch token.type {
                case .PAREN_LEFT: {
                    skip_body = true
                    fn.start = token.location
                    fn.start_index = lookup_index
                }
                case .RETURNS: {
                    function_has_returns = true
                }
                case .TYPE_ANY, .TYPE_BOOL, .TYPE_FLOAT, .TYPE_INT, .TYPE_PTR, .TYPE_STR: {
                    if function_has_returns {
                        function_returns_count += 1
                    } else {
                        function_has_arguments = true
                        function_arguments_count += 1
                    }
                }
            }
        }
    }

    // Identifier
    if fn_id_token.type == .WORD {
        id := gen_fn_id(new_index)
        fn.name = fn_id_token.value.(string)
        fn.identifier = id

        for func in program.body {
            if func.identifier == id {
                function_valid = false
                error_at_ast(fn_id_token, "AST__FUNCTION__IDENTIFIER_EXISTS", fn.name)
            }
        }
    } else {
        function_valid = false
        error_at_ast(fn_id_token, "AST__FUNCTION__IDENTIFIER_IS_NOT_A_VALID_WORD")
        panic_execution(.AST)
    }

    // Arguments
    if function_has_arguments {
        arguments_found := false
        arguments_valid := true

        for !arguments_found {
            new_index += 1
            token := program.tokens[new_index]

            #partial switch token.type {
                case .EOF, .PAREN_RIGHT: {
                    arguments_found = true
                    arguments_valid = false
                }
                case .RETURNS, .PAREN_LEFT: {
                    arguments_found = true
                }
                case .TYPE_ANY:   append(&fn.arguments, DataType.ANY)
                case .TYPE_BOOL:  append(&fn.arguments, DataType.BOOL)
                case .TYPE_FLOAT: append(&fn.arguments, DataType.FLOAT)
                case .TYPE_INT:   append(&fn.arguments, DataType.INT)
                case .TYPE_STR:   append(&fn.arguments, DataType.STRING)
            }
        }

        if !arguments_valid || function_arguments_count != len(fn.arguments) {
            function_valid = false
            // TODO: ERROR
        }
    }

    // Returns
    if function_has_returns {
        returns_found := false
        returns_valid := true

        for !returns_found {
            new_index += 1
            token := program.tokens[new_index]

            #partial switch token.type {
                case .EOF, .PAREN_RIGHT: {
                    returns_found = true
                    returns_valid = false
                }
                case .PAREN_LEFT: {
                    returns_found = true
                }
                case .TYPE_ANY:   append(&fn.returns, DataType.ANY)
                case .TYPE_BOOL:  append(&fn.returns, DataType.BOOL)
                case .TYPE_FLOAT: append(&fn.returns, DataType.FLOAT)
                case .TYPE_INT:   append(&fn.returns, DataType.INT)
                case .TYPE_STR:   append(&fn.returns, DataType.STRING)
            }
        }

        if !returns_valid || function_returns_count != len(fn.returns) {
            function_valid = false
            // TODO: ERROR
        }
    }

    for {
        new_index += 1
        token := program.tokens[new_index]

        if token.type == .EOF {
            error_at_ast(token, "AST__FUNCTION__MISSING_CLOSING_STATEMENT")
            panic_execution(.AST)
        }

        if token.type == .PAREN_RIGHT {
            break
        }
    }

    if function_valid {
        append(&program.body, fn)
    }

    return new_index
}

validate_main_fn :: proc(fn: Function_Declaration) {
    if len(fn.arguments) > 0 || len(fn.returns) > 0 {
        error_at_ast(program.tokens[fn.start_index], "AST__MAIN__NO_ARGUMENTS_OR_RETURNS_ALLOWED")
        panic_execution(.AST)
    }
}

generate_ast :: proc() {
    for &fn in program.body {
        skip_rest_of_function := false
        code_level := 0
        stack: [dynamic]StackValue = make([dynamic]StackValue, 0, 4)
        end_token := program.tokens[fn.end_index]

        if fn.name == "main" {
            validate_main_fn(fn)
            program.main_fn_id = fn.identifier
        }

        for arg_type, index in fn.arguments {
            append(&stack, StackValue{
                identifier = gen_arg_name(index),
                type = arg_type,
            })
        }

        for index := fn.start_index; index < fn.end_index; index += 1 {
            token := program.tokens[index]
            token_stack_id := gen_stack_name(index)

            if skip_rest_of_function {
                break
            }

            switch token.type {
            case .CONSTANT_FALSE:
                append(&fn.body, Literal{
                    identifier = token_stack_id,
                    type = .BOOL,
                    value = false,
                })

                append(&stack, StackValue{
                    identifier = token_stack_id,
                    type = .BOOL,
                })
            case .CONSTANT_FLOAT:
                append(&fn.body, Literal{
                    identifier = token_stack_id,
                    type = .FLOAT,
                    value = token.value.(f64),
                })

                append(&stack, StackValue{
                    identifier = token_stack_id,
                    type = .FLOAT,
                })
            case .CONSTANT_INT:
                append(&fn.body, Literal{
                    identifier = token_stack_id,
                    type = .INT,
                    value = token.value.(int),
                })

                append(&stack, StackValue{
                    identifier = token_stack_id,
                    type = .INT,
                })
            case .CONSTANT_STRING:
                append(&fn.body, Literal{
                    identifier = token_stack_id,
                    type = .STRING,
                    value = token.value.(string),
                })

                append(&stack, StackValue{
                    identifier = token_stack_id,
                    type = .STRING,
                })
            case .CONSTANT_TRUE:
                append(&fn.body, Literal{
                    identifier = token_stack_id,
                    type = .BOOL,
                    value = true,
                })

                append(&stack, StackValue{
                    identifier = token_stack_id,
                    type = .BOOL,
                })
            case .PAREN_RIGHT:
                if code_level == 0 {
                    // TODO: check if this ever happens
                    skip_rest_of_function = true
                    error_at_ast(token, "GENERAL__COMPILER_BUG")
                    panic_execution(.AST)
                } else {
                    code_level -= 1
                }
            case .PAREN_LEFT:
                code_level += 1
            case .EOF:
                skip_rest_of_function = true
                error_at_ast(token, "GENERAL__COMPILER_BUG")
                panic_execution(.AST)
            case .FUNCTION:
                skip_rest_of_function = true
                error_at_ast(token, "AST__BODY__FUNCTION_DECLARATION_NOT_ALLOWED")
            case .MINUS:
                if len(stack) < 2 {
                    skip_rest_of_function = true
                    error_at_ast(token, "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT", 2, len(stack))
                } else {
                    b := pop(&stack)
                    a := pop(&stack)

                    append(&fn.body, BinaryArithmeticExpression{
                        identifier = token_stack_id,
                        left_type = a.type,
                        right_type = b.type,
                        operation = "-",
                    })

                    append(&stack, StackValue{
                        identifier = token_stack_id,
                        type = .INT,
                    })
                }
            case .PERCENT:
                if len(stack) < 2 {
                    skip_rest_of_function = true
                    error_at_ast(token, "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT", 2, len(stack))
                } else {
                    b := pop(&stack)
                    a := pop(&stack)

                    append(&fn.body, BinaryArithmeticExpression{
                        identifier = token_stack_id,
                        left_type = a.type,
                        right_type = b.type,
                        operation = "%",
                    })

                    append(&stack, StackValue{
                        identifier = token_stack_id,
                        type = .INT,
                    })
                }
            case .PLUS:
                if len(stack) < 2 {
                    skip_rest_of_function = true
                    error_at_ast(token, "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT", 2, len(stack))
                } else {
                    // TODO: Check types
                    b := pop(&stack)
                    a := pop(&stack)

                    append(&fn.body, BinaryArithmeticExpression{
                        identifier = token_stack_id,
                        left_type = a.type,
                        right_type = b.type,
                        operation = "+",
                    })

                    append(&stack, StackValue{
                        identifier = token_stack_id,
                        type = .INT,
                    })
                }
            case .PRINT:
                native_fn := get_native_fn(.PRINT)

                if len(stack) < 1 {
                    skip_rest_of_function = true
                    error_at_ast(token, "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT", 1, len(stack))
                } else {
                    a := pop(&stack)

                    append(&fn.body, NativeCall{
                        argument_ids = { a.identifier },
                        callee = .PRINT_STATEMENT,
                    })
                }
            case .RETURNS:
            case .SLASH:
                if len(stack) < 2 {
                    skip_rest_of_function = true
                    error_at_ast(token, "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT", 2, len(stack))
                } else {
                    b := pop(&stack)
                    a := pop(&stack)

                    append(&fn.body, BinaryArithmeticExpression{
                        identifier = token_stack_id,
                        left_type = a.type,
                        right_type = b.type,
                        operation = "/",
                    })

                    append(&stack, StackValue{
                        identifier = token_stack_id,
                        type = .INT,
                    })
                }
            case .STAR:
                if len(stack) < 2 {
                    skip_rest_of_function = true
                    error_at_ast(token, "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT", 2, len(stack))
                } else {
                    b := pop(&stack)
                    a := pop(&stack)

                    append(&fn.body, BinaryArithmeticExpression{
                        identifier = token_stack_id,
                        left_type = a.type,
                        right_type = b.type,
                        operation = "*",
                    })

                    append(&stack, StackValue{
                        identifier = token_stack_id,
                        type = .INT,
                    })
                }
            case .TYPE_ANY:
            case .TYPE_BOOL:
            case .TYPE_FLOAT:
            case .TYPE_INT:
            case .TYPE_PTR:
            case .TYPE_STR:
            case .UNKNOWN:
            case .WORD:
                word := token.value.(string)
                f, f_ok := find_fn_by_name(word)

                switch {
                case f_ok:
                    if len(stack) < len(f.arguments) {
                        skip_rest_of_function = true
                        error_at_ast(
                            token,
                            "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT",
                            len(f.arguments),
                            len(stack),
                        )
                    } else {
                        fcall := FunctionCall{
                            callee = f.identifier,
                            identifier = token_stack_id,
                        }

                        #reverse for arg in f.arguments {
                            a := pop(&stack)

                            if arg != .ANY && a.type != arg {
                                skip_rest_of_function = true
                                // TODO: Generic error should be replaced for specific one (with types)
                                error_at_ast(token, "AST__BODY__INCORRECT_STACK_VALUE_TYPES")
                            } else {
                                append(&fcall.argument_ids, a.identifier)
                            }
                        }

                        for ret, rind in f.returns {
                            ret_id := gen_ret_name(fn.identifier, rind)

                            append(&stack, StackValue{
                                identifier = ret_id,
                                type = ret,
                            })

                            append(&fcall.return_ids, ret_id)
                        }

                        append(&fn.body, fcall)
                    }
                }
            }
        }

        // Check for RETURN
        if len(fn.returns) > 0 {
            if len(stack) != len(fn.returns) {
                error_at_ast(
                    end_token,
                    "AST__BODY__MISSING_STACK_VALUES_EXPECTED_GOT",
                    len(fn.returns),
                    len(stack),
                )
            } else {
                rt_exp := ReturnExpression{}

                #reverse for ret in fn.returns {
                    a := pop(&stack)

                    if a.type != ret {
                        skip_rest_of_function = true
                        // TODO: Generic error should be replaced for specific one (with types)
                        error_at_ast(end_token, "AST__BODY__INCORRECT_STACK_VALUE_TYPES")
                    } else {
                        append(&rt_exp.identifiers, a.identifier)
                    }
                }

                append(&fn.body, rt_exp)
            }
        }

        if len(stack) > 0 {
            error_at_ast(end_token, "AST__BODY__STACK_NOT_EMPTY")
        }

        delete(stack)
    }
}

/** This entry function to create AST has to take care of the program creation so it can
  * be transpiled later on. To do so, this function does the following:
  *     1- Register all functions
  *     2- Generate AST
  * Checks go first because we want to make sure the AST creation is correct.
  */
ast_run :: proc() {
    // Register functions
    for index := 0; index < len(program.tokens); index += 1 {
        token := program.tokens[index]

        if token.type == .FUNCTION {
            index = register_function(index)
        } else if token.type != .EOF {
            error_at_ast(token, "AST__GLOBAL__INVALID_SCOPE")
            panic_execution(.AST)
        }
    }

    generate_ast()

    if len(program.errors) > 0 {
        panic_execution(.AST)
    }
}
