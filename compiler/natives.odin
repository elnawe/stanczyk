package main

import "core:slice"

Native_Function_Id :: enum {
    ADD_FLOAT,
    ADD_INT,
    CONCAT_STR,
    PRINT,
}

Native_Function_Definition :: struct {
    code: string,
    args: []DataType,
    rets: []DataType,
}

native_fns := map[Native_Function_Id]Native_Function_Definition{
        .ADD_FLOAT = {
            code = "_add(f64)",
            args = { .FLOAT, .FLOAT },
            rets = { .FLOAT, },
        },
        .ADD_INT = {
            code = "_add(int)",
            args = { .INT, .INT },
            rets = { .INT, },
        },
        .CONCAT_STR = {
            code = "_concat()",
            args = { .STRING, .STRING },
            rets = { .STRING, },
        },
        .PRINT = {
            code = "_print()",
            args = { .ANY, },
            rets = {},
        },
}

get_native_by_id :: proc(id: Native_Function_Id) -> Native_Function_Definition {
    return native_fns[id]
}
