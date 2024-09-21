package main

import "core:fmt"
import "core:mem"
import "core:strings"

VALUE :: union {
    int,
    f64,
    string,
    bool,
}

STACK : [dynamic]VALUE

_push :: proc(v: VALUE) {
    append(&STACK, v)
}

_pop :: proc() -> VALUE {
    return pop(&STACK)
}

_print :: proc() {
    fmt.print(_pop())
}

_add :: proc($T: typeid) {
    b := _pop().(T)
    a := _pop().(T)
    _push(a + b)
}

_concat :: proc() {
    b := _pop().(string)
    a := _pop().(string)
    _push(strings.concatenate({ a, b, }))
}

_sub_int :: proc() {
    b := _pop().(int)
    a := _pop().(int)
    _push(a - b)
}

_mul_int :: proc() {
    b := _pop().(int)
    a := _pop().(int)
    _push(a * b)
}

_div_int :: proc() {
    b := _pop().(int)
    a := _pop().(int)
    _push(a / b)
}

_mod_int :: proc() {
    b := _pop().(int)
    a := _pop().(int)
    _push(a % b)
}

main :: proc() {
    arena : mem.Arena
    data : [256]byte
    mem.arena_init(&arena, data[:])
    STACK = make([dynamic]VALUE, 0, 16, mem.arena_allocator(&arena))
    sk__fn_main()
}
