package main

import "core:fmt"
import "core:os"
import "core:strings"

Code_Generator :: struct {
    builder: strings.Builder,
    file: os.Handle,
}

BASE_INDENT :: 4

codegen: Code_Generator

cleanup_file :: proc() {
    if os.exists(cargs.odin_file) {
        os.remove(cargs.odin_file)
    }
}

write :: proc{
    write_float,
    write_int,
    write_str,
    write_value,
}

add_indent :: proc(indent: int) {
    for i in 0..<indent * BASE_INDENT {
        strings.write_string(&codegen.builder, " ")
    }
}

add_newline :: proc(newline: int) {
    for i in 0..<newline {
        strings.write_string(&codegen.builder, "\n")
    }
}

write_float :: proc(number: f64, indent: int = 0, newline: int = 0) {
    add_indent(indent)
    strings.write_f64(&codegen.builder, number, 'f')
    add_newline(newline)
}

write_int :: proc(number: int, indent: int = 0, newline: int = 0) {
    add_indent(indent)
    strings.write_int(&codegen.builder, number)
    add_newline(newline)
}

write_str :: proc(str: string, indent: int = 0, newline: int = 0) {
    add_indent(indent)
    strings.write_string(&codegen.builder, str)
    add_newline(newline)
}

write_value :: proc(val: Value, indent: int = 0, newline: int = 0) {
    switch v in val {
    case bool:
        str_val := val.(bool) ? "true" : "false"
        write(str_val, indent, newline)
    case f64: write(val.(f64), indent, newline)
    case int: write(val.(int), indent, newline)
    case string: write(val.(string), indent, newline)
    }
}

flush :: proc() {
    os.write_string(codegen.file, strings.to_string(codegen.builder))
    strings.builder_reset(&codegen.builder)
}

write_bootstrap :: proc() {
    bootstrap := #load("./bootstrap/bootstrap.odin", string)
    write(bootstrap)
    write("", 0, 1)
    flush()
}

codegen_run :: proc() {
    codegen.builder = strings.builder_make()
    err: os.Errno

    cleanup_file()

    codegen.file, err = os.open(cargs.odin_file, os.O_CREATE)
    defer os.close(codegen.file)

    if err != os.ERROR_NONE {
        fmt.println("ERROR: Temp file error create")
    }

    write_bootstrap()

    for fn in program.body {
        arguments: [dynamic]string
        defer delete(arguments)

        write(strings.concatenate({ "// ", fn.name, }), 0, 1)

        if fn.name == "main" {
            write("sk__fn_main :: proc() {", 0, 1)
        } else {
            write(strings.concatenate({ fn.identifier, " :: proc() {", }), 0, 1)
        }

        for stmt in fn.body {
            switch v in stmt {
            case BinaryArithmeticExpression:
                switch v.operation {
                case "-": write("sk__substract()", 1, 1)
                case "*": write("sk__multiply()", 1, 1)
                case "/": write("sk__divide()", 1, 1)
                case "%": write("sk__modulo()", 1, 1)
                }
            case FunctionCall:
                write(strings.concatenate({ v.callee, "()", }), 1, 1)
            case Literal:
                write("_push(", 1, 0)
                write(v.value)
                write(")", 0, 1)
            case Native_Call:
                write(v.code, 1, 1)
            case ReturnExpression:
            }
        }

        write("}", 0, 2)

        flush()
    }
}
