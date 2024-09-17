package main

import "core:strconv"
import "core:strings"

PROGRAM_FUNCTION_NAME :: "sk_fn__"
LOCAL_FUNCTION_ARG    :: "sk_arg__"
LOCAL_FUNCTION_RET    :: "ret__"
LOCAL_FUNCTION_STACK  :: "sk_stack__"

find_fn_by_name :: proc(fn_name: string) -> (Function_Declaration, bool) {
    result: Function_Declaration
    found := false

    for fn in program.body {
        if fn.name == fn_name {
            found = true
            result = fn
        }
    }

    return result, found
}

get_data_type_str :: proc(d: DataType) -> string {
    result: string

    switch d {
    case .ANY: result = "any"
    case .BOOL: result = "bool"
    case .FLOAT: result = "f64"
    case .INT: result = "int"
    case .STRING: result = "string"
    }

    return result
}

gen_arg_name :: proc(number: int) -> string {
    buf: [4]byte
    number_str := strconv.itoa(buf[:], number)
    return strings.concatenate({ LOCAL_FUNCTION_ARG, number_str, }),
}

gen_fn_id :: proc(id: int) -> string {
    buf: [4]byte
    number_str := strconv.itoa(buf[:], id)
    return strings.concatenate({ PROGRAM_FUNCTION_NAME, number_str, }),
}

gen_ret_name :: proc(fn_id: string, number: int) -> string {
    buf: [4]byte
    number_str := strconv.itoa(buf[:], number)
    return strings.concatenate({ LOCAL_FUNCTION_RET, fn_id, "_", number_str, })
}

gen_stack_name :: proc(number: int) -> string {
    buf: [4]byte
    number_str := strconv.itoa(buf[:], number)
    return strings.concatenate({ LOCAL_FUNCTION_STACK, number_str, }),
}

get_os_extension :: proc(filename: string) -> string {
    result: string

    when ODIN_OS == .Windows {
        if strings.has_suffix(filename, ".exe") {
            result = filename
        } else {
            result = strings.concatenate({ filename, ".exe", })
        }
    }

    return result
}
